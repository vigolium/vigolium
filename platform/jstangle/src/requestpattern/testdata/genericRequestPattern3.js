getV1UserDomainContacts: c.query({
    query: function (c) {
        return {
            url: "/v1/user-domain/contacts",
            cookies: {
                zlp_token: c.zlpToken
            },
            headers: {
                Authorization: c.authorization
            },
            params: {
                limit: c.limit,
                page: c.page
            }
        }
    }
})

function s(e, t) {
    try {
        return (0, i.graphqlApiHelper)({
            url: r.In + "/user-management/v1/graphql",
            headers: (0, a.A)({}, e, {
                ROPRO_DEVICE_INFO: navigator.userAgent
            }),
            query: "mutation submitAsusFeedback {\n        create_asus_feedback(\n          input: {\n            action: FEEDBACK_PROVIDED\n            languageCode: " + l + "\n            pageContext: \"" + t.pageContext + "\"\n            answers: [\n              { questionId: \"" + t.answers[0].questionId + "\", value: " + t.answers[0].value + " }\n              { questionId: \"" + t.answers[1].questionId + "\", value: " + t.answers[0].value + " }\n            ]\n            tellUsMore: \"" + t.tellUsMore + "\"\n          }\n        )\n      }"
        });
    } catch (e) {
        console.error(e);
        throw e;
    }
}