package main

import(
	"strconv"
	"strings"
	"bufio"
	"log"
	"os"
	"errors"
)

// ipvsモジュールのコネクション情報を取得
// ipvsモジュールのVIPにアクセスするIPアドレスを取ってくる
func GetIPMap() (map[string]string, error) {
	f, err := os.Open("/proc/net/ip_vs_conn")
	if err != nil {
        f.Close()
        return nil, errors.New("can't open /proc/net/ip_vs_conn")
	}
	defer f.Close()

	lines := make([]string, 0, 500)

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	if scanErr := scanner.Err(); scanErr != nil {
        return nil, errors.New("can't read /proc/net/ip_vs_conn")
	}

    ipvsConnSet := make(map[string]string)

	for _, v := range lines[1:] {
        line := strings.Split(v, " ")
        ipvsConnSet[HexStringToIPString(line[1])] = HexStringToIPString(line[5])
	}

    return ipvsConnSet, nil
}

// 16進文字列を1バイト毎10進に変換しIPアドレスの文字列をかえす
// 0A040227 => 10.4.2.39
func HexStringToIPString(hexString string) string {
	ips := make([]string, 0)
	for i := 0; i < 4; i++ {
		v, err := strconv.ParseInt(hexString[i*2:i*2+2], 16, 32)
        if err != nil {
            log.Fatal(err)
        }
		ips = append(ips, strconv.FormatInt(v, 10))
	}
	return strings.Join(ips, ".")
}

func HexStringToPortString(hexString string) string {
	port, _ := strconv.ParseInt(hexString, 16, 32)
	return strconv.FormatInt(port, 10)
}
