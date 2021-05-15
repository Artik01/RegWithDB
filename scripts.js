function Login() {
	let login = document.getElementById("login").value;
	let password = document.getElementById("password").value;
	
	loginReq(login, password)
}

var token="";

async function loginReq(login, password) {
	let res = await fetch("http://localhost:8080/login", {
		method: 'POST', // *GET, POST, PUT, DELETE, etc.
		mode: 'cors', // no-cors, *cors, same-origin
		cache: 'no-cache', // *default, no-cache, reload, force-cache, only-if-cached
		credentials: 'same-origin', // include, *same-origin, omit
		headers: {
		  'Content-Type': 'application/json'
		  // 'Content-Type': 'application/x-www-form-urlencoded',
		},
		redirect: 'follow', // manual, *follow, error
		referrerPolicy: 'no-referrer', // no-referrer, *client
		body: '{"login":"'+login+'","password":"'+password+'"}'// body data type must match "Content-Type" header
	  });
	let inf = await res;
	console.log(inf);
	
	let jso = await res.text();
	if (jso=="unknown") {
		document.getElementById("auth").innerHTML = "Incorrect username or password";
	} else {
		document.getElementById("auth").innerHTML = "";
		token = jso;
		document.getElementById("login").style.visibility="hidden";
		document.getElementById("password").style.visibility="hidden";
		document.getElementById("auth").style.visibility="hidden";
		document.getElementById("logBtn").style.visibility="hidden";
		document.getElementById("regBtn").style.visibility="hidden";
		document.getElementById("forL").style.visibility="hidden";
		document.getElementById("forP").style.visibility="hidden";
	}
}

function pop() {
	if (token=="") {
		document.getElementById("resp").innerHTML = "Unauthorized";
	} else {
		let request = document.getElementById("req").value;
		if (request=="") {
			document.getElementById("resp").innerHTML = "Empty request field";
			
		} else {
			getReq(request);
		}
	}
}

async function getReq(request) {
	let res = await fetch("http://localhost:8080/data", {
		method: 'GET', // *GET, POST, PUT, DELETE, etc.
		mode: 'cors', // no-cors, *cors, same-origin
		cache: 'no-cache', // *default, no-cache, reload, force-cache, only-if-cached
		credentials: 'same-origin', // include, *same-origin, omit
		headers: {
		  'Content-Type': 'application/json',
		  'Token': token,
		  'Request':request
		  // 'Content-Type': 'application/x-www-form-urlencoded',
		},
		redirect: 'follow', // manual, *follow, error
		referrerPolicy: 'no-referrer', // no-referrer, *client
	  });
	let inf = await res;
	console.log(inf);
	if (res.status==401) {
		document.getElementById("resp").innerHTML = "Unauthorized";
		return;
	}
	
	let jso = await res.text();
	if (jso == "failed") {
		document.getElementById("resp").innerHTML = "Unsuported request";
	} else {
		document.getElementById("resp").innerHTML = jso;
	}
}

function redirectReg() {
	window.location.replace("http://localhost:8080/register");
}

function redirectMain() {
	window.location.replace("http://localhost:8080");
}

function register() {
	let login = document.getElementById("login").value;
	let password = document.getElementById("password").value;
	let secret = document.getElementById("secret").value;
	
	if (login == "" || password == "" || secret == "") {
		document.getElementById("reg").innerHTML = "Empty field";
	} else  {
		regReq(login, password, secret)
	}
}

async function regReq(login, password, secret) {
	let res = await fetch("http://localhost:8080/register", {
		method: 'POST', // *GET, POST, PUT, DELETE, etc.
		mode: 'cors', // no-cors, *cors, same-origin
		cache: 'no-cache', // *default, no-cache, reload, force-cache, only-if-cached
		credentials: 'same-origin', // include, *same-origin, omit
		headers: {
		  'Content-Type': 'application/json'
		  // 'Content-Type': 'application/x-www-form-urlencoded',
		},
		redirect: 'follow', // manual, *follow, error
		referrerPolicy: 'no-referrer', // no-referrer, *client
		body: '{"login":"'+login+'","password":"'+password+'","secret":"'+secret+'"}'// body data type must match "Content-Type" header
	  });
	let inf = await res;
	console.log(inf);
	
	let jso = await res.text();
	if (jso == "success") {
		document.getElementById("reg").innerHTML = "";
		redirectMain();
	} else {
		document.getElementById("reg").innerHTML = "This login already is used";
	}
}
