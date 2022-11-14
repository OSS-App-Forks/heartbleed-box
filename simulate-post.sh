echo "Simulating login with username=$1 and password=$2 and possible user agent $3"

s22(){
    echo "Mozilla/5.0 (Linux; Android 12; SM-S906N Build/QP1A.190711.020; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/80.0.3987.119 Mobile Safari/537.36"
}
edge(){
    echo "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/42.0.2311.135 Safari/537.36 Edge/12.246"
}

if [ -z "$3" ]; then
    curl -k -vvv -s -m .1 -d "username=$1&password=$2" https://127.0.0.1:4433/submit
else
    curl -k -vvv -s -m .1 -d "username=$1&password=$2" https://127.0.0.1:4433/submit -A "$($3)"
fi