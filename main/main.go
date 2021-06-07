package main

import (
	"crypto/sha1"
	"encoding/json"
	"fmt"
	"github.com/jinzhu/configor"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
)

type PostFields struct {
	Action      string
	Username    string
	Password    string
	ACid        int
	Ip          string
	Chksum      string
	Info        string
	N           int
	type_       int
	os          string
	name        string
	DoubleStack int
}

type Challenge struct {
	Username string
	Ip       string
}

type CFG struct {
	Account string
	Passwd string
	Ip string
}

var cfg= &CFG{}
var timeMs int
var cookie string
func (cg *CFG)LoadYml(){
	err := configor.Load(cg, "./config.yml")
	if err != nil {
		log.Printf("conf load failed, err is: %v\n", err)
	}
	log.Printf("cfg is: %v\n", cfg)
}
func main() {
	cfg.LoadYml()
	CreatVM()
	for {
		postValues := &PostFields{
			Action:      "login",
			Username:    cfg.Account,
			Password:    cfg.Passwd,
			ACid:        1,
			Ip:          cfg.Ip,
			Chksum:      "",
			Info:        "",
			N:           200,
			type_:       1,
			os:          "Windows 10",
			name:        "Windows",
			DoubleStack: 0,
		}
		//获取token
		challenge := getChallenge()
		token := challenge
		//token := "28101732b5c8810d90dc4404079edb317a59932d52ac851a2a2aed6505655d5c"

		time.Sleep(time.Second)
		//获取postValue的info字段
		postValues.Info = generateInfo(postValues, token)
		fmt.Println(postValues.Info)

		//获取密码token加密md5值
		hmd5 := getHmd5(postValues.Password, token)
		chkStr := getChkStr(token, hmd5, postValues)
		postValues.Chksum = getChkSumUseSha1(chkStr)
		//postValues.Chksum = getChkSum(chkStr)

		//portal认证
		resp := srunPortal(postValues)
		fmt.Println(resp)
		if SuccessLogin(resp) {
			fmt.Println("登陆成功！")
			getDetails()
			break
		} else {
			fmt.Println("登陆失败！")
			getDetails()
			//rand.Intn(5)
			time.Sleep( 5* time.Second)
		}
	}

}

func SuccessLogin(resp string) bool {
	if len(resp) < 2 {
		return false
	}
	reg := regexp.MustCompile(`"error":"(.*?)",`)
	if reg.FindStringSubmatch(resp)[1] == "ok" {
		return true
	} else {
		return false
	}
}

func getChkSumUseSha1(str string) string {
	res := ""
	sum := sha1.Sum([]byte(str))
	for _, v := range sum {
		res += fmt.Sprintf("%x", v)
	}
	return res
}

func srunPortal(datas *PostFields) string {
	url := "https://gw.buaa.edu.cn/cgi-bin/srun_portal"
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		log.Print(err)
		os.Exit(1)
	}
	q := req.URL.Query()
	q.Add("callback", "jQuery112404477632700586378_"+strconv.Itoa(timeMs))
	q.Add("_", strconv.Itoa(timeMs+2))
	q.Add("action", datas.Action)
	q.Add("username", datas.Username)
	q.Add("password", datas.Password)
	q.Add("ac_id", strconv.Itoa(datas.ACid))
	q.Add("ip", datas.Ip)
	q.Add("chksum", datas.Chksum)
	q.Add("info", datas.Info)
	q.Add("n", strconv.Itoa(datas.N))
	q.Add("type", strconv.Itoa(datas.type_))
	q.Add("os", datas.os)
	q.Add("name", datas.name)
	q.Add("double_stack", strconv.Itoa(datas.DoubleStack))

	req.URL.RawQuery = q.Encode()
	req.Header.Set("Cookie", cookie)
	req.Header.Set("Connection", "keep-alive")
	//req.Header.Set("sec-ch-ua",`Not;A Brand";v="99", "Google Chrome";v="91", "Chromium";v="91`)
	//req.Header.Set("sec-ch-ua-mobile","?0")
	//req.Header.Set("Sec-Fetch-Dest","empty")
	//req.Header.Set("Sec-Fetch-Mode","cors")
	//req.Header.Set("Sec-Fetch-Site","same-origin")
	//req.Header.Set("X-Requested-With","XMLHttpRequest")
	req.Header.Set("User-Agent", "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.77 Safari/537.36")
	fmt.Println(req.Header)
	fmt.Println(req.URL.String())
	// Output:
	// http://api.themoviedb.org/3/tv/popular?another_thing=foo+%26+bar&api_key=key_from_environment_or_flag
	var resp *http.Response
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		log.Print(err)
	}

	defer resp.Body.Close()
	result, _ := ioutil.ReadAll(resp.Body)
	fmt.Printf("[x] %v\n", string(result))

	return string(result)
}

func getChkSum(str string) string {
	sum, err := Vm.Call("sha1", nil, str)
	if err != nil {
		fmt.Printf("sha1 failed with err:%v\n", err)
		panic("")
	}
	return sum.String()
}

func getChkStr(token, hmd5 string, values *PostFields) string {
	var chkstr = token + values.Username
	chkstr += token + hmd5
	chkstr += token + strconv.Itoa(values.ACid)
	chkstr += token + values.Ip
	chkstr += token + strconv.Itoa(values.N)
	chkstr += token + strconv.Itoa(values.type_)
	chkstr += token + values.Info
	values.Password = "{MD5}" + hmd5
	return chkstr
}

func generateInfo(postValue *PostFields, token string) string {
	jsonp, err := json.Marshal(&struct {
		Username string `json:"username"`
		Passwd   string `json:"password"`
		Ip       string `json:"ip"`
		Acid     string `json:"acid"`
		EncVer   string `json:"enc_ver"`
	}{
		Username: postValue.Username,
		Passwd:   postValue.Password,
		Ip:       postValue.Ip,
		Acid:     strconv.Itoa(postValue.ACid),
		EncVer:   "srun_bx1",
	})
	if err != nil {
		fmt.Printf("marshal json with err :%v", err)
		panic("")
	}
	//fmt.Printf("jsonp :%#v", string(jsonp))
	xEncodeValue, err := Vm.Call("xEncode", nil, string(jsonp), token)
	if err != nil {
		fmt.Printf("call xEncode failed with err :%v", err)
		log.Panic("")
	}
	base64EncodeValue, err := Vm.Call("base64encode", nil, xEncodeValue)
	if err != nil {
		fmt.Printf("call base64.encode failed with err :%v\n", err)

	}

	return "{SRBX1}" + base64EncodeValue.String()
}

func getHmd5(password, token string) string {
	hdm5V, err := Vm.Call("md5", nil, password, token)
	if err != nil {
		panic(err)
	}
	return hdm5V.String()
}

func getChallenge() string {
	url := "https://gw.buaa.edu.cn/cgi-bin/get_challenge"
	data := Challenge{
		Username: cfg.Account,
		Ip:       cfg.Ip,
	}
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		log.Print(err)
		os.Exit(1)
	}
	q := req.URL.Query()
	timeMs = int(time.Now().UnixNano() / 1e6)
	q.Add("callback", "jQuery112404477632700586378_"+strconv.Itoa(timeMs))
	q.Add("_", strconv.Itoa(timeMs+1))
	q.Add("username", data.Username)
	q.Add("ip", data.Ip)
	req.URL.RawQuery = q.Encode()
	req.Header.Set("User-Agent", "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.77 Safari/537.36")
	req.Header.Set("Connection", "keep-alive")
	//req.Header.Set("sec-ch-ua",`Not;A Brand";v="99", "Google Chrome";v="91", "Chromium";v="91`)
	//req.Header.Set("sec-ch-ua-mobile","?0")
	//req.Header.Set("Sec-Fetch-Dest","empty")
	//req.Header.Set("Sec-Fetch-Mode","cors")
	//req.Header.Set("Sec-Fetch-Site","same-origin")
	fmt.Println(req.URL.String())
	var resp *http.Response
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		log.Print(err)
	}
	defer resp.Body.Close()
	result, _ := ioutil.ReadAll(resp.Body)
	fmt.Printf("[x] %v\n", string(result))
	cookie = strings.Split(resp.Header.Get("Set-Cookie"), ";")[0]
	fmt.Println("cookie", cookie)


	return findExg(string(result))
}

func findExg(s string) string {
	reg := regexp.MustCompile(`"challenge":"(.*?)",`)

	return reg.FindStringSubmatch(s)[1]
}

func getDetails() {
	url := "https://gw.buaa.edu.cn/cgi-bin/rad_user_info"
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		log.Print(err)
		os.Exit(1)
	}
	q := req.URL.Query()
	time1 := int(time.Now().UnixNano() / 1e6)
	q.Add("callback", "jQuery112404477632700586378_"+strconv.Itoa(time1))
	q.Add("_", strconv.Itoa(time1+2))

	req.URL.RawQuery = q.Encode()
	req.Header.Set("User-Agent", "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.77 Safari/537.36")
	req.Header.Set("Connection", "keep-alive")
	req.Header.Set("Cookie", cookie)
	//req.Header.Set("sec-ch-ua",`Not;A Brand";v="99", "Google Chrome";v="91", "Chromium";v="91`)
	//req.Header.Set("sec-ch-ua-mobile","?0")
	//req.Header.Set("Sec-Fetch-Dest","empty")
	//req.Header.Set("Sec-Fetch-Mode","cors")
	//req.Header.Set("Sec-Fetch-Site","same-origin")
	fmt.Println(req.URL.String())
	var resp *http.Response
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		log.Print(err)
	}
	defer resp.Body.Close()
	result, _ := ioutil.ReadAll(resp.Body)
	fmt.Printf("[x] %v\n", string(result))
}
