r.toSupport = function (e) {
    e.preventDefault();
    var t = r.props;
    var n = t.zpTransID;
    var a = t.amount;
    var l = t.description;
    var c = {
        zp_trans_id: n,
        trans_time: t.transTime,
        title: l,
        trans_amount: a
    };
    (0, u.T8)("/support-center/feedback/transaction-history", c, {
        rawUri: true
    });
};

r.toSupport = function (e) {
    e.preventDefault();
    var t = r.props;
    var n = t.zpTransID;
    var a = t.amount;
    var l = t.description;
    var c = {
        zp_trans_id: n,
        trans_time: t.transTime,
        title: l,
        trans_amount: a
    };
    (0, u.T8)(`/support-center/feedback/transaction-history/${id}`, c, {
        rawUri: true
    });
};

