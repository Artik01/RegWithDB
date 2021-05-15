package main

import (
	"net/http"
	"io"
	"fmt"
	"encoding/json"
	"crypto/sha256"
	"encoding/base64"
	"crypto/hmac"
	"time"
	"strings"
	_ "embed"
)

var Base64alphabet string = "QWEqweRTYrtyUIOuioPpASDasdFGHfghJKLjklZXCzxcVBNvbnMm?:1234567890"
var Encoder *base64.Encoding = base64.NewEncoding(Base64alphabet)

var Mutex chan int = make(chan int, 1)

//go:embed scripts.js
var JS string
//go:embed main/index.html
var mainHTML string
//go:embed register/index.html
var regHTML string

var ID int = 1

type UserData struct {
	Login string    `json:"login"`
	Password string `json:"password"`
}

type RegData struct {
	Login string    `json:"login"`
	Password string `json:"password"`
	Secret string	`json:"secret"`
}

type User struct {
	ID int
	login string
	secret string
	passwordHash [sha256.Size]byte
}

type Data struct {
	Login string	`json:"name"`
	ExpDate int64	`json:"exp"`
}

var userDB []User

var TokenDB []string

var DB map[string]int

func loginHandler(w http.ResponseWriter, req *http.Request) {
	w.Header().Add("Access-Control-Allow-Methods", "OPTIONS, POST")
	w.Header().Add("Access-Control-Allow-Headers", "content-type")
	w.Header().Add("Access-Control-Allow-Origin","*")
	if req.Method == "OPTIONS" {
		w.WriteHeader(204)
	} else if req.Method == "POST" {
		data, err := io.ReadAll(req.Body)
		req.Body.Close()
		if err != nil {return }
		var v UserData
		err = json.Unmarshal(data, &v)
		if err != nil {fmt.Println(err); return}
		
		for _, u := range userDB {
			if u.login == v.Login && u.passwordHash == sha256.Sum256([]byte(v.Password)) {
				io.WriteString(w, createToken(u))
				return
			}
		}
		
		io.WriteString(w, "unknown")
	} else {
		w.WriteHeader(405)
	}
}

func createToken(user User) string {
	now := time.Now()
	Header:=`{"alg":"HS256","typ":"JWT"}`
	
	Payload:=`{"name":"`+user.login+`","sub":"`+fmt.Sprint(user.ID)+`","exp":`+fmt.Sprint(now.Add(time.Hour).Unix())+`}`
	token:=Encoder.EncodeToString([]byte(Header))+"."+Encoder.EncodeToString([]byte(Payload))
	
	mac:=hmac.New(sha256.New,[]byte(user.secret))
	mac.Write([]byte(token))
	sum:=mac.Sum(nil)
	token+="."+Encoder.EncodeToString(sum)
	
	TokenDB = append(TokenDB,token)
	return token
}

func getHandler(w http.ResponseWriter, req *http.Request) {
	w.Header().Add("Access-Control-Allow-Methods", "OPTIONS, GET")
	w.Header().Add("Access-Control-Allow-Headers", "content-type, token, request")
	w.Header().Add("Access-Control-Allow-Origin","*")
	if req.Method == "OPTIONS" {
		w.WriteHeader(204)
	} else if req.Method == "GET" {
		token:= req.Header.Get("Token")
		
		indx:=strings.LastIndex(token,".")
		var secret string
		for _, u := range userDB {
			if u.login==GetLogin(token) {
				secret = u.secret
			}
		}
		if !ValidMAC([]byte(token[:indx]),[]byte(token[indx+1:]),[]byte(secret)) {
			w.WriteHeader(401)
			return
		}
		
		for _, t := range TokenDB {
			if t == token {
				if time.Now().After(GetExp(token)) {
					DeleteToken(token)
					w.WriteHeader(401)
					return
				}
				name := req.Header.Get("Request")
				age, ok := DB[name]
				if ok {
					w.Write([]byte(fmt.Sprintf("%s's age: %d", name, age)))
				} else {
					w.Write([]byte("failed"))
				}
				return
			}
		}
		w.WriteHeader(401)
	} else {
		w.WriteHeader(405)
	}
}

func regHandler(w http.ResponseWriter, req *http.Request) {
	w.Header().Add("Access-Control-Allow-Methods", "OPTIONS, GET, POST")
	w.Header().Add("Access-Control-Allow-Headers", "content-type")
	w.Header().Add("Access-Control-Allow-Origin","*")
	if req.Method == "OPTIONS" {
		w.WriteHeader(204)
	} else if req.Method == "GET" {
		if req.URL.String() == "/register" {
			w.Write([]byte(regHTML))
		} else {
			w.Write([]byte(""))
		}
	} else if req.Method == "POST" {
		data, err := io.ReadAll(req.Body)
		req.Body.Close()
		if err != nil {return }
		
		var v RegData
		err = json.Unmarshal(data, &v)
		if err != nil {fmt.Println(err); return}
		
		for _, u := range userDB {
			if u.login == v.Login {
				io.WriteString(w, "exist")
				return
			}
		}
		
		userDB = append(userDB, User{ID, v.Login, v.Secret, sha256.Sum256([]byte(v.Password))})
		ID++
		io.WriteString(w, "success")
	} else {
		w.WriteHeader(405)
	}
}
func baseHandler(w http.ResponseWriter, req *http.Request) {
	w.Header().Add("Access-Control-Allow-Methods", "OPTIONS, GET")
	w.Header().Add("Access-Control-Allow-Headers", "content-type")
	w.Header().Add("Access-Control-Allow-Origin","*")
	if req.Method == "OPTIONS" {
		w.WriteHeader(204)
	} else if req.Method == "GET" {
		if req.URL.String() == "/" {
			w.Write([]byte(mainHTML))
		} else if req.URL.String() == "/scripts.js" {
			w.Write([]byte(JS))
		} else {
			w.Write([]byte(""))
		}
	} else {
		w.WriteHeader(405)
	}
}

func ValidMAC(message, messageMAC, key []byte) bool {
	mac := hmac.New(sha256.New, key)
	mac.Write(message)
	expectedMAC := mac.Sum(nil)
	return hmac.Equal(messageMAC, []byte(Encoder.EncodeToString(expectedMAC)))
}

func GetExp(t string) time.Time {
	t1:=strings.Index(t,".")
	t2:=strings.LastIndex(t,".")
	
	PayloadDecoded:=t[t1+1:t2]
	str, _:=Encoder.DecodeString(PayloadDecoded)
	var d Data
	json.Unmarshal(str,&d)
	return time.Unix(d.ExpDate,0)
}

func GetLogin(t string) string {
	t1:=strings.Index(t,".")
	t2:=strings.LastIndex(t,".")
	
	PayloadDecoded:=t[t1+1:t2]
	str, _:=Encoder.DecodeString(PayloadDecoded)
	var d Data
	json.Unmarshal(str,&d)
	return d.Login
}

func DeleteToken(token string) {
	<-Mutex
	i := 0
	var t string
	for i, t = range TokenDB {
		if t == token {
			break
		}
	}
	
	TokenDB = append(TokenDB[:i], TokenDB[i+1:]...)
	Mutex <- 1
}

func main() {
	DB = make(map[string]int)
	DB["Artur"]=20
	DB["Alina"]=25
	DB["Samantha"]=14
	DB["Max"]=40
	DB["Artjom"]=50
	Mutex <- 1
	http.HandleFunc("/login", loginHandler)
	http.HandleFunc("/data", getHandler)
	http.HandleFunc("/register", regHandler)
	http.HandleFunc("/", baseHandler)
	
	err := http.ListenAndServe(":8080", nil)
	panic(err)
}

