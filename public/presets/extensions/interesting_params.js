// interesting_params.js
// Passive module: Identifies typical parameters susceptible to specific
// vulnerability classes such as IDOR, SQLi, RCE, SSRF, LFI, SSTI,
// Open Redirect, and Debug/Admin endpoints.
//
// References:
//   - https://cheatsheetseries.owasp.org/index.html
//   - https://portswigger.net/burp/documentation/scanner/vulnerabilities-list
//   - https://github.com/bugcrowd/HUNT/blob/master/Burp/conf/issues.json
//   - https://github.com/1ndianl33t/Gf-Patterns

var REFERENCES = [
  "https://cheatsheetseries.owasp.org/index.html",
  "https://portswigger.net/burp/documentation/scanner/vulnerabilities-list",
  "https://github.com/bugcrowd/HUNT/blob/master/Burp/conf/issues.json",
  "https://github.com/1ndianl33t/Gf-Patterns"
].join("\n- ");

var REMEDIATION = "Identifies typical parameters susceptible to specific vulnerability classes " +
  "such as IDOR, SQLi, RCE, and more. Manual review is recommended.\n\n## References:\n- " + REFERENCES;

// Each rule: { id, label, params (Set via vigolium.utils.toSet) }
var RULES = [
  {
    id: "sqli",
    label: "SQL Injection",
    params: vigolium.utils.toSet("cat,category,column,comment,delete,email,fetch,field,filter,from,group,id,input,keyword,name,number,order,orderby,param,params,password,post,process,query,report,results,role,row,search,sel,select,sleep,sort,string,table,term,text,title,update,user,username,value,view,where")
  },
  {
    id: "idor",
    label: "IDOR",
    params: vigolium.utils.toSet("account,doc,edit,email,group,guid,hash,id,index,item_id,key,no,number,object_id,order,order_id,post_id,product_id,profile,ref,reference,report,sequence,session_id,session_token,token,user,user_id,uuid")
  },
  {
    id: "rce",
    label: "OS Command Injection",
    params: vigolium.utils.toSet("arg,args,argument,cli,cmd,code,command,daemon,dir,downloa,download,exec,execute,file,filename,flag,func,functio,input,ip,jump,load,log,module,option,options,param,parameter,params,path,payload,ping,print,process,query,read,reg,req,run,script,scripts,shell")
  },
  {
    id: "lfi",
    label: "File Inclusion / Path Traversal",
    params: vigolium.utils.toSet("action,cat,conf,content,date,detail,dir,directory,doc,document,download,file,filename,folder,inc,include,input,layout,locate,location,name,page,path,pdf,php_path,prefix,resource,root,show,site,style,target,template,type,url,view")
  },
  {
    id: "ssrf",
    label: "SSRF",
    params: vigolium.utils.toSet("access,callback,cfg,clone,continue,create,data,dbg,dest,dir,disable,doc,document,domain,edit,enable,endpoint,exec,execute,feed,fetch,file,filename,folder,grant,host,html,img,link,load,location,make,modify,navigation,next,open,out,page,path,php_path,port,redirect,reference,rename,request,reset,return,root,service,shell,show,site,source,style,target,test,to,toggle,uri,url,val,validate,view,window")
  },
  {
    id: "ssti",
    label: "SSTI",
    params: vigolium.utils.toSet("activity,content,data,id,input,layout,name,page,param,preview,redirect,render,template,theme,tpl,view")
  },
  {
    id: "debug",
    label: "Debug / Admin Parameter",
    params: vigolium.utils.toSet("access,adm,admin,alter,cfg,clone,config,create,dbg,debug,delete,disable,edit,enable,exec,execute,grant,load,make,modify,rename,reset,root,shell,test,toggle")
  },
  {
    id: "open-redirect",
    label: "Open Redirect",
    params: vigolium.utils.toSet("image_url,open,callback,checkout,checkout_url,continue,data,dest,destination,dir,domain,feed,file,file_name,file_url,folder,folder_url,forward,from_url,go,goto,host,html,image_url,img_url,load_file,load_url,login_url,logout,navigation,next,next_page,out,page,page_url,path,port,redir,redirect,redirect_to,redirect_uri,redirect_url,reference,return,returnto,return_path,return_to,return_url,rt,rurl,show,site,target,to,uri,url,val,validate,view,window")
  }
];

var URL_IN_PARAM_RE = /=https?:\/\/\S+/;

module.exports = {
  id: "interesting-params",
  name: "Interesting Parameters In Request",
  description: "Identifies typical parameters susceptible to specific vulnerability classes such as IDOR, SQLi, RCE, and more",
  type: "passive",
  severity: "suspect",
  confidence: "tentative",
  scope: "request",
  tags: ["recon", "params", "light"],
  scanTypes: ["per_request"],

  scanPerRequest: function(ctx) {
    if (!ctx.request) return null;

    // Use vigolium.parse to extract query and body
    var parsed = ctx.request.url ? vigolium.parse.url(ctx.request.url) : null;
    var query = parsed ? parsed.query : "";
    var body = ctx.request.raw ? vigolium.parse.request(ctx.request.raw) : null;
    var bodyStr = body ? body.body : "";

    var combined = query + (bodyStr ? "&" + bodyStr : "");
    if (!combined) return null;

    // Use vigolium.utils.extractParamNames for deduplicated, lowercased param names
    var paramNames = vigolium.utils.extractParamNames(combined);
    if (paramNames.length === 0) return null;

    // Classify: category -> list of matched param names
    var matches = {};
    var matchOrder = [];

    for (var i = 0; i < paramNames.length; i++) {
      var p = paramNames[i];
      for (var j = 0; j < RULES.length; j++) {
        var rule = RULES[j];
        if (rule.params[p]) {
          if (!matches[rule.id]) {
            matches[rule.id] = { label: rule.label, params: [] };
            matchOrder.push(rule.id);
          }
          if (matches[rule.id].params.indexOf(p) === -1) {
            matches[rule.id].params.push(p);
          }
        }
      }
    }

    // Check for URL-in-parameter pattern
    if (URL_IN_PARAM_RE.test(combined)) {
      if (!matches["url-in-param"]) {
        matches["url-in-param"] = { label: "URL in Parameter", params: [] };
        matchOrder.push("url-in-param");
      }
      var urlRe = /([A-Za-z0-9_.\-\[\]]+)=https?:\/\/\S+/g;
      var um;
      while ((um = urlRe.exec(combined)) !== null) {
        var pName = um[1].toLowerCase();
        if (matches["url-in-param"].params.indexOf(pName) === -1) {
          matches["url-in-param"].params.push(pName);
        }
      }
    }

    if (matchOrder.length === 0) return null;

    // Build description
    var details = [];
    var remarkTags = [];
    for (var k = 0; k < matchOrder.length; k++) {
      var catId = matchOrder[k];
      var cat = matches[catId];
      details.push("- **" + cat.label + "**: " + cat.params.join(", "));
      remarkTags.push("interesting-param:" + catId);
    }

    var description = "Parameters in this request match patterns associated with known vulnerability classes:\n" +
      details.join("\n") +
      "\n\n" + REMEDIATION;

    // Annotate the HTTP record remarks if DB is available
    if (ctx.record && ctx.record.uuid) {
      ctx.record.addRemarks(remarkTags);
    }

    return [{
      url: ctx.request.url,
      matched: matchOrder.map(function(id) { return matches[id].label; }).join(", "),
      name: "Interesting Parameters In Request",
      description: description,
      severity: "suspect"
    }];
  }
};
