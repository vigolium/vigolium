// exec_recon.js — Active module using vigolium.utils.exec()
// Demonstrates shell command execution for reconnaissance.
// Runs dig or nslookup on the target host and reports DNS records as findings.

module.exports = {
  id: "exec-recon",
  name: "DNS Recon via Exec",
  type: "active",
  severity: "info",
  description: "Uses exec() to run DNS lookups on the target host",
  tags: ["recon", "dns", "exec"],
  scanTypes: ["per_host"],

  scanPerHost: function(ctx) {
    var url = ctx.request.url || "";
    var host = url.split("//")[1];
    if (!host) return null;
    host = host.split("/")[0].split(":")[0];

    var result = vigolium.utils.exec("dig +short " + host + " A 2>/dev/null || nslookup " + host + " 2>/dev/null");
    if (!result || result.exitCode !== 0 || !result.stdout) return null;

    var output = result.stdout.trim();
    if (!output) return null;

    return [{
      url: ctx.request.url,
      matched: host,
      name: "DNS records for " + host,
      description: "Resolved addresses:\n" + output,
      severity: "info"
    }];
  }
};
