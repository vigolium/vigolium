$(document).ready(function(){
	if(typeof console === "undefined") {
	    console = {
	        log: function() { }	        
	    };
	}
	checkUrl();
});

function checkUrl(){
	var url = location.href;
	if(url.indexOf("#") != -1){
		var id = url.substring(url.indexOf("#") + 1);
		if(id.substring(0,4) != "test"){
			loadForm(id);		
		}else{
			openPage(id + ".html");	
		}
	}else{
		loadHome();		
	}
}

function loadTest(element){
	openPage(element.innerHTML + ".html");
}

function openPage(url){
	$('#content').load(url);
}

function loadRandomAllowedPage(){
	$('#content').html("Random valid page " + (Math.random()*1000000000000000000));
}

function loadForbiddenPage(element){
	$('#content').html("FORBIDDEN_PAGE derived from " + element);
	console.log("Forbidden element loaded");
	console.log(element);
}

function loadHome(){
	$('#content').load("home.html", function(){
		   $("#randomStyle").css("borderLeft", (Math.random()*800) + "px solid red");
		   var day = Math.floor(Math.random()*20)+1;
		   var month = Math.floor(Math.random()*11)+1;
		   $("#randomDate").html(day + "-" + month + "-2012");
	});
}

function getFormValues(id){
	var ret = "";
	ret += document.getElementById("text" + id).value + ";";
	ret += document.getElementById("text2" + id).value + ";";
	ret += document.getElementById("checkbox" + id).checked + ";";
	ret += document.getElementById("radio" + id).checked + ";";
	ret += document.getElementById("select" + id).options[document.getElementById("select" + id).selectedIndex].innerHTML + ";";
	ret += document.getElementById("textarea" + id).value;
	return ret;
}

function getForm(id){
	var ret = "";
	ret +='<input type="text" id="text' + id + '"/>';
	ret +='<input id="text2' + id + '"/>';
	ret +='<input type="checkbox" id="checkbox' + id + '" />';
	ret +='<input type="radio" id="radio' + id + '" />';
	ret +='<select id="select' + id + '">';
	ret +='<option>OPTION1</option>';
	ret +='<option>OPTION2</option>';
	ret +='<option>OPTION3</option>';
	ret +='<option>OPTION4</option>';
	ret +='</select>';
	ret +='<textarea id="textarea' + id + '"></textarea>';
	ret +="<a href='javascript:void(0)' onclick='submitForm" + id + "(\"" + id + "\")'>Submit " + id + "</a>";
	return ret;
}

function loadForm(id){
	$('#content').html(getForm(id));
}

function submitFormRandom(id){
	$("#content").html("RESULT_RANDOM_INPUT" + " " + getFormValues(id) + "");
}

function submitFormManual(id){
	$("#content").html("RESULT_MANUAL_INPUT" + " " + getFormValues(id) + "");
}

function submitFormMultiple(id){
	$("#content").html("RESULT_MULTIPLE_INPUT" + " " + getFormValues(id) + "");
}