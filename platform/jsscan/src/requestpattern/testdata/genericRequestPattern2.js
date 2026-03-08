this.createOrder = function (e) {
    var t = {
        appid: e.appid,
        zalopayid: e.zalopayid,
        appinfo: e.appinfo
    },
        n = {
            reqdate: Date.now().toString(),
            data: JSON.stringify(t)
        };
    return xt.post("/cpscore/app/createmultibillorder", Et().stringify(n))
};

this.getSupplier = function (e) {
    return xt.get("/cpscore/app/getsupplier", {
        params: {
            reqdate: Date.now().toString(),
            data: {
                appid: e.appid,
                zalopayid: e.zalopayid
            }
        }
    })
}

