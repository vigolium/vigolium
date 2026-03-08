$(document).ready(function(){
	openPage("home.html");
	setEventHandlers();
	//addError("how rude");
	//addError("how kewl");
});

function setEventHandlers(){
	$('#info').click(function(){ openPage("info.html") } );
	$('#papers').click(function(){ openPage("papers.html") } );
	$('#home').click(function(){ openPage("home.html") } );
	$('#ignore').click(function(){ addError("Crawljax should ignore me") } );
}

function openPage(page){
	$('#content').load(page);
}

function addError(msg){
	$('#errors').show();
	$('#errors').html($('#errors').html() + "<p>ERROR: " + msg + "</p>");
}



function saveContact(msg){
	var content = "<h1>" + msg + "</h1>";
	var gender = (document.getElementById("male").checked ? "male" : "female");
	content += "<h2>Gender: " + gender + "<br />";
	content += "Name: " + $('#name').val() + "<br />";
	content += "Phone: " + $('#phone').val() + "<br />";
	content += "Mobile: " + $('#mobile').val() + "<br />";
	content += "Type: " + document.getElementById("type").options[document.getElementById("type").selectedIndex].value + "<br />";
	content += "Active: " + document.getElementById("active").checked;
	content += "</h2>";
	$('#content').html(content);
}

function afterRandomInput(){
	var content = "<h2>filled in random values</h2><h3>";
	content += "text: " + document.getElementById("text").value + "<br />";
	content += "checkbox: " + document.getElementById("checkbox").checked + "<br />";
	content += "radio: " + document.getElementById("radio").checked + "<br />";
	content += "Select: " + document.getElementById("select").value;
	content += "</h3>";
	
	$('#content').html(content);
	
}
