var x = function () {
    var e = Object(r.a)(i.a.mark(function e() {
        var t;
        var n;
        var r;
        var c;
        var s;
        var o;
        var j = arguments;
        return i.a.wrap(function (e) {
            while (true) {
                switch (e.prev = e.next) {
                    case 0:
                        t = j.length > 0 && j[0] !== undefined ? j[0] : [];
                        n = j.length > 1 && j[1] !== undefined ? j[1] : 400;
                        if (Object(b.h)(t)) {
                            e.next = 4;
                            break;
                        }
                        return e.abrupt("return", []);
                    case 4:
                        e.prev = 4;
                        r = Object(u.chunk)(t, n);
                        c = r.map(function (e) {
                            var t = `/hyatt-yapmo/rest/atom/getByPostIds?post_ids=${e.join(",")}`;
                            return O(function () {
                                return l.d.get(t);
                            });
                        });
                        e.next = 9;
                        return Promise.all(c);
                    case 9:
                        s = e.sent;
                        o = s.reduce(function (e, t) {
                            if (t.data && t.data.atoms) {
                                var n = t.data.atoms.map(function (e) {
                                    if (e.comment_id) {
                                        return d.a.CommentAtomFactory(e.atom_id, e, e.comment_id);
                                    } else {
                                        return d.a.createAtom(e.atom_id, e);
                                    }
                                });
                                e.push.apply(e, Object(a.a)(n));
                            }
                            return e;
                        }, []);
                        return e.abrupt("return", o);
                    case 14:
                        e.prev = 14;
                        e.t0 = e.catch(4);
                        console.error(e.t0);
                        return e.abrupt("return", []);
                    case 18:
                    case "end":
                        return e.stop();
                }
            }
        }, e, null, [[4, 14]]);
    }));
    return function () {
        return e.apply(this, arguments);
    };
}();
