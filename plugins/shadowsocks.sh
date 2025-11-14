#!/bin/sh

VERSION=1.0.1
PROC=ss-redir
PR_NAME="Shadowsocks-libev"
PR_TYPE="Прозрачный прокси"
#DESCRIPTION="Протокол Shadowsocks"
CONF="/opt/etc/kvl/shadowsocks.json"
ARGS="-u -c $CONF"
# Передаваемые параметры работы плагина ( метод на текущий момент может быть tproxy - Прозрачный прокси и wg - POINT-TO-POINT тунель)
METOD=tproxy
#Как пересылать TCP пакеты из iptables в модуль через dnat или tproxy
TCP_WAY=dnat
#============================================= тестирование соединения ==================================================================
PROC_TEST=ss-local
PING_COUNT=10
PING_TIMEOUT=1
TEST_PORT=1889
URL_TEST="http://cachefly.cachefly.net/10mb.test"
#========================================================================================================================================

ansi_red="\033[1;31m";
ansi_white="\033[1;37m";
ansi_green="\033[1;32m";
ansi_yellow="\033[1;33m";
ansi_blue="\033[36m";
#ansi_bell="\007";
#ansi_blink="\033[5m";
#ansi_rev="\033[7m";
#ansi_ul="\033[4m";
ansi_std="\033[m";


if [ -t 1 ]; then
  INTERACTIVE=1
else
  INTERACTIVE=0
fi
# Вычисляем текущую ширину экрана для печати линий определенной ширины
length=$(stty size 2>/dev/null | cut -d' ' -f2)
[ -n "${length}" ] && [ "${length}" -gt 80 ] && LENGTH=$((length*2/3)) || LENGTH=68

print_line() {
	len=$((LENGTH))
	printf "%${len}s\n" | tr " " "-"
}

resolve_ip() {
    local host="$1"
    local dns_server="127.0.0.1"
    nslookup "$host" "$dns_server" 2>/dev/null | \
        awk '/^Address [0-9]+: / && $3 !~ /^127\./ && $3 !~ /:/ { print $3; exit }'
}

# ------------------------------------------------------------------------------------------
#
#	 Читаем значение переменной из ввода данных в цикле
#	 $1 - заголовок для запроса
#	 $2 - переменная в которой возвращается результат
#	 $3 - тип вводимого значения
#		 digit - цифра
#		 password - пароль без показа вводимых символов
#
# ------------------------------------------------------------------------------------------
read_value() {
	header="$(echo "${1}" | tr -d '?')"
	type="${3}"

	while true; do
		echo -en "${header}${ansi_std} [Q-выход]  "
		if [ "${type}" = 'password' ]; then read -rs value; else read -r value; fi
		if [ -z "${value}" ]; then
				echo
				print_line
				echo -e "${ansi_red}Данные не должны быть пустыми!"
				echo -e "${ansi_green}Попробуйте ввести значение снова...${ansi_std}"
				print_line
		elif echo "${value}" | grep -qiE '^Q$' ; then
				eval "${2}=q"
				break
		elif [ "${type}" = 'digit' ] && ! echo "${value}" | grep -qE '^[[:digit:]]{1,6}$'; then
				echo
				print_line
				echo -e "${ansi_red}Введенные данные должны быть цифрами!"
				echo -e "${ansi_green}Попробуйте ввести значение снова...${ansi_std}"
				print_line
		elif [ "${type}" = 'password' ] && ! echo "${value}" | grep -qE '^[a-zA-Z0-9]{8,1024}$' ; then
				echo
				print_line
				echo -e "${ansi_green}Пароль должен содержать минимум 8 знаков и"
				echo -e "${ansi_green}ТОЛЬКО буквы и ЦИФРЫ, ${ansi_red}без каких-либо спец символов!${ansi_std}"
				echo -e "${ansi_red}Попробуйте ввести его снова...${ansi_std}"
				print_line
		else
				eval "${2}=\"\$value\""
				break
		fi
	done
}

# экранировщик для replace-части
escape_sed_replace() {
	printf '%s' "$1" | sed -e 's/\\/\\\\/g' -e 's/&/\\&/g' -e 's/[\/]/\\&/g'
}

parser_url(){
  	local SSR_LINK="$1"
  	[ "$INTERACTIVE" -eq 1 ] && [ -z "$SSR_LINK" ] && read_value "${ansi_green}🔗 Ведите кодированную ссылку в формате ss://:" SSR_LINK
  	[ -z "$SSR_LINK" ] || [[ "$SSR_LINK" =~ ^[Qq]$ ]]  && return 1	
	SSR_SERVER_IP=""; SSR_SERVER_PORT=""; SSR_SERVER_CRYPT=""; SSR_SERVER_PASSWD=""; SSR_DESC=""
	if [[ -n "${SSR_LINK}" && "${#SSR_LINK}" -gt 6 ]] ; then
    # Извлечение тега (всё после #)
    SSR_DESC=$(echo "${SSR_LINK}" | grep -oP '(?<=#).*' || echo "")
    # Удаление параметров после ? и тега после # для обработки основной части
		SSR_LINK="$(echo "${SSR_LINK}" | sed -E 's/(.*)[#?\/]\?.*|(.*)#.*/\1\2/')"
		password=$(echo "${SSR_LINK}" | grep -oP "(?<=ss://).*?(?=@)" | base64 -d )
		SSR_SERVER_PASSWD=$(echo "${password}" | cut -d ":" -f 2)
		SSR_SERVER_CRYPT=$(echo "${password}" | cut -d ":" -f 1)
		SSR_SERVER_IP=$(echo "${SSR_LINK}" | grep -oP "(?<=@).*?(?=:)")
		SSR_SERVER_PORT=$(echo "${SSR_LINK}" | sed 's/.*@.*:\([0-9]\{1,6\}\).*/\1/')
	else
		echo -e "${ansi_red}Ссылка пуста или слишком коротка! Введите корректную ссылку!${ansi_std}"
		return 1
	fi
	if [ -z "${SSR_SERVER_PASSWD}" ] || [ -z "${SSR_SERVER_CRYPT}" ] || [ -z "${SSR_SERVER_IP}" ] || [ -z "${SSR_SERVER_PORT}" ] ; then
		echo -e "${ansi_red}Извлеченные данные не корректны! Введите ссылку с корректными данными!${ansi_std}"
		return 1
	fi
 # Если тег пустой, запрашиваем описание у пользователя
  if [ -z "$SSR_DESC" ] && [ "$INTERACTIVE" -eq 1 ]; then
    read_value "${ansi_white}Описание не найдено, вы можете ввести описание соединения:${ansi_std}" SSR_DESC
    # Если пользователь ввёл пустое описание, устанавливаем значение по умолчанию
    [ -z "$SSR_DESC" ] && SSR_DESC="no-description"
  fi
	return 0
}

set_param(){
	if [ -f "${CONF}" ] ; then
		# Экранируем символы для применения в sed
		ESCAPED_PASSWD=$(escape_sed_replace "$SSR_SERVER_PASSWD")
		sed -i "s/\(\"server\":\).*/\1 \"${SSR_SERVER_IP}\",/; 			\
        s/\(\"desc\":\).*/\1 \"${SSR_DESC}\",/; 	\
				s/\(\"server_port\":\).*/\1 ${SSR_SERVER_PORT},/; 		\
				s/\(\"password\":\).*/\1 \"${ESCAPED_PASSWD}\",/; 	\
				s/\(\"method\":\).*/\1 \"${SSR_SERVER_CRYPT}\",/;" 		\
				"${CONF}" &>/dev/null
		if [ $? ]; then
			echo -e "Конфигурацию ${CONF} изменена ${ansi_green}УСПЕШНО${ansi_std}"
			return 0
		else
			echo -e "Конфигурацию ${CONF} изменена ${ansi_red}C ОШИБКАМИ${ansi_std}"
			return 1
		fi
	else
		print_line
		echo -e "${ansi_red}Не обнаружен файл ${CONF}.${ansi_std}"
		print_line
		return 1
	fi
}

set_param_manual(){
	SSR_SERVER_IP=""; SSR_SERVER_PORT=""; SSR_SERVER_CRYPT=""; SSR_SERVER_PASSWD=""; SSR_DESC=""
	echo "Необходимо ввести следующие данные:"
	echo -e "${ansi_green}Хост${ansi_std} сервера, его ${ansi_green}порт, пароль доступа${ansi_std} и ${ansi_green}метод шифрования${ansi_std}"
	echo -e "${ansi_blue}Пожалуйста, последовательно введите эти данные ниже.${ansi_std}"
	echo -e "Можно ввести ${ansi_yellow}q или Q${ansi_std} и выйти из программы"
	print_line
	read_value "Ведите доменное имя или IP адрес сервера:" SSR_SERVER_IP
	[[ "$SSR_SERVER_IP" =~ ^[Qq]$ ]] && return 1
	read_value "Ведите порт сервера:" SSR_SERVER_PORT 'digit'
	[[ "$SSR_SERVER_PORT" =~ ^[Qq]$ ]] && return 1
	read_value "Ведите метод шифрования на стороне сервера:" SSR_SERVER_CRYPT
	[[ "$SSR_SERVER_CRYPT" =~ ^[Qq]$ ]] && return 1
	read_value "Ведите пароль сервера:" SSR_SERVER_PASSWD 'password'
	[[ "$SSR_SERVER_PASSWD" =~ ^[Qq]$ ]] && return 1
  read_value "${ansi_white}Описание не найдено, вы можете ввести описание соединения:${ansi_std}" SSR_DESC
  [[ "$SSR_DESC" =~ ^[Qq]$ ]] && return 1
  [ -z "$SSR_DESC" ] && SSR_DESC="no-description"
	echo
	set_param
}

ping_start_bg() {
    local ping_host="$1"
    (
	  trap 'kill "$pid" 2>/dev/null' EXIT			
	  ping -c "$PING_COUNT" -W "$PING_TIMEOUT" "$ping_host" 2>&1 &
	  pid=$!
      #ping -c "$PING_COUNT" -W "$PING_TIMEOUT" "$ping_host" 2>&1 
	  wait "$pid"
      echo -e "${ansi_yellow}⚠️  Пинг завершился, но тесты всё ещё выполняются (зависит от скорости соединения), пожалуйста, подождите...${ansi_std}"
    ) & 
    PING_PID=$!
}

start_speed_test() {
  local log_file="$1"
  local max_attempts=2
  local attempt=1
  local timeout=90

  while [ $attempt -le $max_attempts ]; do
    speed_test=$(curl -s --max-time "$timeout" -w "%{http_code}|%{size_download}|%{time_namelookup}|%{time_connect}|%{time_starttransfer}|%{time_total}|%{speed_download}\n" \
        -x socks5://127.0.0.1:$TEST_PORT -o /dev/null "$URL_TEST")

    IFS='|' read -r http_code size_file t_namelookup t_connect t_starttransfer t_total speed_bytes <<EOF
$speed_test
EOF
    # Проверка на успех: код 200 и размер хотя бы 10 МБ (10485760 байт)
    if [ "$http_code" = "200" ] && [ "$size_file" -ge 10485760 ]; then
      return 0
    fi
	download_time_s=$(awk "BEGIN { printf \"%.1f\", $t_total - $t_starttransfer }")
	size_mb=$(awk "BEGIN { printf \"%.3f\", ($size_file * 8) / 1024000 }")
    speed_mbps=$(awk "BEGIN { printf \"%.2f\", ($speed_bytes * 8) / 1000000 }")
    echo "Попытка $attempt из $max_attempts не удалась (код: $http_code, размер: $size_mb МБ, скорость $speed_mbps Мб/с, затраченное время $download_time_s сек), повтор ..." >> "$log_file"
	t_total_int=$(printf "%.0f" "$t_total")
	if [ "$t_total_int" -ge "$(timeout - 2)" ]; then
		break
	fi	
    attempt=$((attempt + 1))
    sleep 5
  done
  return 1
}

# Если пользователь прервет основной скрипт убить и дочерние если создавались
cleanup_test() {
  if [ -n "$PING_PID" ] && kill -0 "$PING_PID" 2>/dev/null; then
    kill "$PING_PID" 2>/dev/null
  fi
  if [ -n "$SS_PID" ] && kill -0 "$SS_PID" 2>/dev/null; then
    kill "$SS_PID" 2>/dev/null
  fi  
}

test_url(){
  local temp_pid="/tmp/ss-test.pid"
  local temp_log="/tmp/ss-test.log"
  local temp_std="/tmp/ss-test.std"
  trap cleanup_test EXIT INT TERM
  # запускаем пинг на сервер в фоне
  echo -e "${ansi_blue}Запускаем ss-local с тестовым конфигом и начинаем тесты в фоне${ansi_std}"
  echo -e "${ansi_white}Одновременно запускаем пинг сервера — он завершится после окончания тестов${ansi_std}"
  ping_start_bg "$SSR_SERVER_IP"
  : > "$temp_std"
    # Запуск ss-local во фоне
  rm -f "$temp_pid"		
  "$PROC_TEST" -s "$SSR_SERVER_IP" -p "$SSR_SERVER_PORT" -l "$TEST_PORT" -k "$SSR_SERVER_PASSWD" -m "$SSR_SERVER_CRYPT" -f "$temp_pid" -b 127.0.0.1 -v >"$temp_log" 2>&1 &
  while [ ! -s "$temp_pid" ]; do sleep 1; done
  SS_PID=$(cat $temp_pid)
  # Ждём запуска процесса (макс 10 секунд)
    i=0
    while [ "$i" -lt 10 ]; do
      if kill -0 "$SS_PID" 2>/dev/null; then
        echo -e "${ansi_green}✅ ss-local test instance был запущен (PID: $SS_PID)${ansi_std}" >> $temp_std
        break
      fi
    sleep 1
    i=$((i + 1))
  done
  # Проверка: успел ли стартовать
  if ! kill -0 "$SS_PID" 2>/dev/null; then
    echo -e "${ansi_red}❌ Не удалось запустить ss-local test instance${ansi_std}" >> $temp_std
    [ -f "$temp_log" ] && { echo "--- Содержимое лога ---"; cat "$temp_log"; } >> $temp_std
    return 1
  fi
  # проверяем в лог файле что сервер запустился 
  i=0
  success=0
  while [ $i -lt 10 ]; do
      sleep 1
      # Если порт открыт — успех
      if netstat -lnpt 2>/dev/null | grep -q ":$TEST_PORT"; then
        success=1
        break
      fi
      if grep -q "Failed to start" "$temp_log"; then
        success=0
        break
      fi
      i=$((i + 1))
  done

  if [ "$success" -eq 0 ]; then
      echo -e "${ansi_red}❌ Ошибка: не открылся порт проверки: $TEST_PORT${ansi_std}" >> $temp_std
      cat "$temp_log"
      kill "$SS_PID" 2>/dev/null
      rm -f "$temp_log" "$temp_pid"
      return 1
  fi

  echo -e "${ansi_white}🔍 Проверка IP через прокси на myip.wtf ...${ansi_std}" >> $temp_std
  local output
  local flag_speed_test=0
  output=$(curl -s --max-time 10 -x socks5://127.0.0.1:$TEST_PORT https://myip.wtf/json)
  # проверяем что ответ получен
  if echo "$output" | grep -q '"YourFuckingIPAddress"'; then
    echo -e "${ansi_green}✅ Успешно получены данные с сайта myip.wtf:${ansi_std}" >> $temp_std
    echo -e "${ansi_white}   🔍 Запускаем проверку скорости ...${ansi_std}" >> $temp_std
    
    if start_speed_test "$temp_std"; then
      # Вычисления с помощью awk
      echo -e "${ansi_green}    ✅ Успешно выполнен тест скорости${ansi_std}" >> $temp_std
      flag_speed_test=1
      latency_ms=$(awk "BEGIN { printf \"%.2f\", ($t_connect - $t_namelookup) * 1000 }")
      wait_ms=$(awk "BEGIN { printf \"%.2f\", ($t_starttransfer - $t_connect) * 1000 }")
      download_time_s=$(awk "BEGIN { printf \"%.2f\", $t_total - $t_starttransfer }")
      speed_mbps=$(awk "BEGIN { printf \"%.2f\", ($speed_bytes * 8) / 1000000 }")
      dns_ms=$(awk "BEGIN { printf \"%.2f\", $t_namelookup * 1000 }")   
    fi  
  fi
  
  if kill "$PING_PID" 2>/dev/null; then
    i=0
    while [ "$i" -lt 5 ]; do
        if ! kill -0 "$PING_PID" 2>/dev/null; then
            break
        fi
        sleep 1
        i=$((i + 1))
    done
    if kill -0 "$PING_PID" 2>/dev/null; then
        echo -e "${ansi_yellow}⚠️ PING не завершился, принудительное убийство${ansi_std}" >> $temp_std
        kill -9 "$PING_PID" 2>/dev/null
    fi
  fi
  # Выводим на экран то что выполнялось паралельно
  cat $temp_std

  # Убить ss-local
  echo -e "${ansi_white}Проверка завершилась, производим остановку ss-local${ansi_std}" 
  if kill "$SS_PID" 2>/dev/null; then
    i=0
    while [ "$i" -lt 5 ]; do
        if ! kill -0 "$SS_PID" 2>/dev/null; then
            break
        fi
        sleep 1
        i=$((i + 1))
    done
    if kill -0 "$SS_PID" 2>/dev/null; then
        echo -e "${ansi_yellow}⚠️ ss-local не завершился, принудительное убийство${ansi_std}"
        kill -9 "$SS_PID" 2>/dev/null
    fi
  fi
   

    # Парсим JSON-ответ
    if echo "$output" | grep -q '"YourFuckingIPAddress"'; then
        echo -e "${ansi_green}✅ Результаты проверок:${ansi_std}"
        echo "$output" | awk '
            /"YourFuckingIPAddress"/   { sub(/^.*: /, ""); gsub(/[",]/,""); print "   🌐 IP         : " $0 }
            /"YourFuckingLocation"/    { sub(/^.*: /, ""); gsub(/[",]/,""); print "   📍 Location   : " $0 }
            /"YourFuckingHostname"/    { sub(/^.*: /, ""); gsub(/[",]/,""); print "   🖥 Hostname    : " $0 }
            /"YourFuckingISP"/         { sub(/^.*: /, ""); gsub(/[",]/,""); print "   🏢 ISP        : " $0 }
            /"YourFuckingCity"/        { sub(/^.*: /, ""); gsub(/[",]/,""); print "   🏙 City        : " $0 }
            /"YourFuckingCountry"/     { sub(/^.*: /, ""); gsub(/[",]/,""); print "   🌎 Country    : " $0 }
        '
        if [ "$flag_speed_test" = "1" ]; then
          print_line
          echo " ⏱️  DNS Lookup:        $dns_ms мс"
          echo " ⏱️  Латентность TCP:   $latency_ms мс"
          echo " ⏱️  Ожидание ответа:   $wait_ms мс"
          echo " ⏱️  Скачивание файла:  $download_time_s сек"
          echo "     Скорость:          $speed_mbps Мбит/с"
        fi

    else
        echo -e "${ansi_red}❌ Протокол Shadowsocks не работает или сайт не отвечает${ansi_std}"
        echo -e "${ansi_white}🔍 Содержимое $temp_log:${ansi_std}"
        print_line
        cat "$temp_log"
    fi
    # Очистка
    rm -f "$temp_pid" "$temp_log" "$temp_std"
}

start(){
	# Запуск демона/применение настроек
	[ "$INTERACTIVE" -eq 1 ] && echo -e -n "$ansi_white Starting $PR_NAME... $ansi_std"
    if pidof "$PROC" >/dev/null; then
	  [ "$INTERACTIVE" -eq 1 ] && echo -e "            $ansi_yellow already running. $ansi_std" || echo '{"status":"alive"}';
      return 0
    fi
    # shellcheck disable=SC2086 
    $PROC $ARGS > /dev/null 2>&1 &
    i=0
    while [ "$i" -lt 10 ]; do
      sleep 1
      if pidof "$PROC" >/dev/null; then
	  	[ "$INTERACTIVE" -eq 1 ] && echo -e "            $ansi_green done. $ansi_std"
        logger "Started $$PR_NAME successfully."
        return 0
      fi
      i=$((i + 1))
    done
	[ "$INTERACTIVE" -eq 1 ] && echo -e "            $ansi_red failed. $ansi_std"
    logger "Failed to start $PR_NAME"
    return 255
}

stop() {
    # Остановка демона/откат
	case "$1" in
		stop | restart)
			[ "$INTERACTIVE" -eq 1 ] && echo -e -n "$ansi_white Shutting down $PROC... $ansi_std"
    		killall "$PROC" 2>/dev/null
    		i=0
    		LIMIT=10
			while [ "$i" -lt "$LIMIT" ]; do
				sleep 1
				if ! pidof "$PROC" >/dev/null; then
					[ "$INTERACTIVE" -eq 1 ] && echo -e "            $ansi_green done. $ansi_std"
					logger "Stopped $PROC successfully."
					return 0
				fi
				i=$((i + 1))
			done
		;;
    	kill)
            [ "$INTERACTIVE" -eq 1 ] && echo -e -n "$ansi_white Killing $PROC... $ansi_std"
            killall -9 $PROC 2>/dev/null
			if ! pidof "$PROC" >/dev/null; then
				[ "$INTERACTIVE" -eq 1 ] && echo -e "            $ansi_green done. $ansi_std"
				logger "Stopped $PROC successfully."
				return 0
			fi			
        ;;
	esac	
	[ "$INTERACTIVE" -eq 1 ] && echo -e "            $ansi_red failed. $ansi_std"	
    logger "Failed to stop $PROC"
    return 255
}

check() {
    [ "$INTERACTIVE" -eq 1 ] && echo -e -n "$ansi_white Checking $PR_NAME... $ansi_std"
    if pidof "$PROC" >/dev/null; then
        [ "$INTERACTIVE" -eq 1 ] && echo -e "            $ansi_green alive. $ansi_std" || echo '{"status":"alive"}';
        return 0
    else
        [ "$INTERACTIVE" -eq 1 ] && echo -e "            $ansi_red dead. $ansi_std" || echo '{"status":"dead"}';
        return 1
    fi
}

case "$1" in
  start)
	start
    ;;
  stop|kill)
	stop "$1"
    ;;
  restart)
    check > /dev/null && stop "$1"
    start
    ;;	
  check|status)
    check
    ;;	
  info)
    desc=$(jq -r '.desc' "$CONF")
    if [ "$INTERACTIVE" -eq 1 ]; then
      echo "Плагин: $PR_NAME Версия плагина: $VERSION"
		  echo "Тип: $PR_TYPE"
		  echo "Описание: $desc"
    else
      echo "{\"name\":\"$PR_NAME\",\"description\":\"$desc\",\"type\":\"$PR_TYPE\",\"method\":\"$METOD\"}"
    fi
    ;;
  get_param)
    local_port=$(jq -r '.local_port' "$CONF")
    server=$(jq -r '.server' "$CONF")
	  mode=$(jq -r '.mode' "$CONF")
    # Проверка поддержки UDP
    if echo "$ARGS" | grep -qw -- '-u' || echo "$mode" | grep -q 'udp'; then
      udp="yes"
    else
      udp="no"
    fi
    ip=$(resolve_ip "$server")
    echo "{\"inface_cli\":\"$PR_NAME\",\"method\":\"$METOD\",\"udp\":\"$udp\",\"tcp_way\":\"$TCP_WAY\",\"tcp_port\":\"$local_port\",\"udp_port\":\"$local_port\",\"server_ip\":\"$ip\"}"
    ;;
  set_param)
	  set_param_manual
	  ;;
  url)
	  case "$2" in
      set)
        # строки вида ss:// — плагин сам разбирает и сохраняет
		    parser_url "$3" && set_param
        ;;
      test)
        parser_url "$3" && test_url
        ;;  
      *)
        echo "Usage: $0 url (set|test)" >&2; exit 1
        ;;  
    esac
    ;;
  *)
    echo "Usage: $0 (start|restart|stop|check|status|info|get_param|url|set_param)" >&2; exit 1
    ;;
esac

