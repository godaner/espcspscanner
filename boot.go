package main

import (
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

func main() {
	ips:=""
	flag.StringVar(&ips,"ips","192.168.1.1-192.168.1.255,192.168.2.1-192.168.2.255,192.168.3.1-192.168.3.255,192.168.6.1-192.168.6.255,192.168.10.1-192.168.10.255","scan ips , eg : 192.168.1.1-192.168.1.255,192.168.2.1-192.168.2.255")
	flag.Parse()
	ipArr:=strings.Split(ips,",")
	s := &ESPCSPScanner{
		IPArr: ipArr,
	}
	s.Scan()

}

type ESPCSPScanner struct {
	IPArr []string
	sync.WaitGroup
}

func (s *ESPCSPScanner) Scan() {
	ch:=make(chan int ,1)
	go func() {
		for {
			select {
			case <-ch:
				fmt.Println("scan end !")
			case <-time.After(30 * time.Second):
				fmt.Println("scan end , timeout !")
				os.Exit(-1)
			}
		}
	}()
	fmt.Println("scan start !")
	for _, ip := range s.IPArr {
		s.scanIp(ip)
	}
	s.Wait()
	ch<-1

}
var i int
func (s *ESPCSPScanner) scanIp(ip string) {
	isRangeIp := false
	var (
		startIp, endIp IP
	)
	ipRange := strings.Split(ip, "-")
	if len(ipRange) >= 2 {
		startIp = IP(ipRange[0])
		endIp = IP(ipRange[1])
		isRangeIp = true
	}
	if isRangeIp {
		ip := &startIp
		s.scanIp(string(*ip))
		for ip.NextIP(&endIp) {
			s.scanIp(string(*ip))
		}
		return
	}
	s.Add(1)
	go func() {
		i++
		if i>10000{
			panic("too many ip")
		}
		defer s.Done()
		url := fmt.Sprintf("http://%v:30001/resource", ip)
		res, _, msgid := httpGetRequest(url)
		if msgid == "" {
			data:=res["data"].(map[string]interface{})
			oem,_:=data["oem"].(string)
			if oem==""{
				oem,_=data["OEM"].(string)
			}
			fmt.Printf("%v : %v-%v-%v\n",ip,oem,data["type"],data["version"])
		}
	}()


}

type IP string

func (i *IP) ParseIP(ipStr string) {
	*i = IP(net.ParseIP(ipStr))
}

// 1,0,-1 > = <
func (i *IP) Eq(ip *IP) (r int64) {
	ip1s := strings.Split(string(*i), ".")
	ip2s := strings.Split(string(*ip), ".")

	r = eq(ip1s[0], ip2s[0])
	if r != 0 {
		return r
	}

	r = eq(ip1s[1], ip2s[1])
	if r != 0 {
		return r
	}
	r = eq(ip1s[2], ip2s[2])
	if r != 0 {
		return r
	}
	r = eq(ip1s[3], ip2s[3])
	if r != 0 {
		return r
	}
	return 0
}
func eq(a, b string) (r int64) {
	ai,_:=strconv.ParseInt(a,10,64)
	bi,_:=strconv.ParseInt(b,10,64)
	if ai > bi {
		return 1
	} else if ai < bi {
		return -1
	}
	return 0
}
func (i *IP) NextIP(maxIP *IP) (success bool) {
	r := i.Eq(maxIP)
	if r == 0 || r > 0 {
		return false
	}

	ip1s := strings.Split(string(*i), ".")
	ip13, _ := strconv.ParseInt(ip1s[3], 10, 64)
	if ip13 != 255 {
		ip13 += 1
		ip1s[3] = fmt.Sprint(ip13)
		*i = IP(strings.Join(ip1s, "."))
		return true
	}
	ip12, _ := strconv.ParseInt(ip1s[2], 10, 64)
	if ip12 != 255 {
		ip12 += 1
		ip13 = 1
		ip1s[2] = fmt.Sprint(ip12)
		ip1s[3] = fmt.Sprint(ip13)
		*i = IP(strings.Join(ip1s, "."))
		return true
	}
	ip11, _ := strconv.ParseInt(ip1s[1], 10, 64)
	if ip11 != 255 {
		ip11 += 1
		ip13 = 1
		ip12 = 1
		ip1s[1] = fmt.Sprint(ip11)
		ip1s[2] = fmt.Sprint(ip12)
		ip1s[3] = fmt.Sprint(ip13)
		*i = IP(strings.Join(ip1s, "."))
		return true
	}
	ip10, _ := strconv.ParseInt(ip1s[0], 10, 64)
	if ip10 != 255 {
		ip10 += 1
		ip11 = 1
		ip13 = 1
		ip12 = 1
		ip1s[0] = fmt.Sprint(ip10)
		ip1s[1] = fmt.Sprint(ip11)
		ip1s[2] = fmt.Sprint(ip12)
		ip1s[3] = fmt.Sprint(ip13)
		*i = IP(strings.Join(ip1s, "."))
		return true
	}
	return false
}

//http get
func httpGetRequest(url string) (map[string]interface{}, string, string) {
	// resp, err := http.Post(common.LocalHostURL+url, "application/json", data)
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr, Timeout: 30 * time.Second}
	reqest, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, "http new request with err" + err.Error(), "E0031"
	}
	resp, err := client.Do(reqest)
	if err != nil {
		return nil, "http get with err" + err.Error(), "E0031"
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, "read all with err" + err.Error(), "E0031"
	}
	result := make(map[string]interface{})
	err = json.Unmarshal(body, &result)
	if err != nil {
		return nil, "unmarshal json with err" + err.Error(), "E0031"
	}
	return result, "", ""
}
