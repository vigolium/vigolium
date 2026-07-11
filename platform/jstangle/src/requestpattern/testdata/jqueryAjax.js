$.ajax({
    url: "ajax.aspx",
    type: "get", //send it through get method
    data: {
        ajaxid: 4,
        UserID: UserID,
        EmailAddress: EmailAddress
    },
    success: function (response) {
        //Do Something
    },
    error: function (xhr) {
        //Do Something to handle error
    }
});

$.ajax({
    url: "ajax.aspx",
    type: "get", //send it through get method
    data: {
        ajaxid: 4,
        UserID: 1,
        EmailAddress: "123@gmail.com"
    },
    success: function (response) {
        //Do Something
    },
    error: function (xhr) {
        //Do Something to handle error
    }
});