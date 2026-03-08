var a = {
    key: "greetingCardsGet",
    value: function (e, t, r) {
        var n = {
            m_uid: e,
            m_access_token: t
        },
            a = gn;
        return this.apiClient.callApi("/greeting/cards", "GET", {}, {}, n, {}, null, [], [], ["*/*"], a, r)
    }
};

var b = {
    key: "ordersCreatePost",
    value: function (e, t, r, n) {
        var a = e,
            o = {
                m_uid: t,
                m_access_token: r
            },
            i = hn;
        return this.apiClient.callApi("/orders/create", "POST", {}, {}, o, {}, a, [], ["*/*"], ["*/*"], i, n)
    }
};

c = {
    key: "orders",
    value: function (e, t, r, n) {
        var a = e,
            i = hn;
        return this.apiClient.callApi("POST", "/orders/get", {}, {}, {
            id: 1
        }, {}, a, [], ["*/*"], ["*/*"], i, n)
    }
};

d = {
    key: "ordersDeletePost",
    value: function (e, t, r, n) {
        var a = e,
            o = JSON.stringify({
                m_uid: t,
                m_access_token: r
            }),
            i = hn;
        return this.apiClient.callApi("/orders/delete", "POST", {}, {}, o, {}, a, [], ["*/*"], ["*/*"], i, n)
    }
};

e = {
    key: "greetingCardsGet",
    value: function (e, t, r) {
        var n = {
            m_uid: e,
            m_access_token: t
        },
            a = gn;
        return (aa, 0)("/greeting/cards", "GET", {}, {}, n, {}, null, [], [], ["*/*"], a, r)
    }
}
e = {
    key: "greetingCardsGet2",
    value: function (e, t, r) {
        var n = {
            m_uid: e,
            m_access_token: t
        },
            a = gn;
        return (aa, 0)(`/greeting/cards/${id}`, "GET", {}, {}, n, {}, null, [], [], ["*/*"], a, r)
    }
}

