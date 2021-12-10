if (history.scrollRestoration) {
    history.scrollRestoration = 'manual';
} else {
    window.onbeforeunload = function () {
        window.scrollTo(0, 0);
    }
}

function search() {
    var input, filter, ul, li, div, form, i, txtValue;
    input = document.getElementById('myInput');
    filter = input.value.toUpperCase();
    ul = document.getElementById("myUL");
    li = ul.getElementsByTagName('li');

    for (i = 0; i < li.length; i++) {
        form = li[i].getElementsByTagName("form")[0];
        div =  form.getElementsByTagName("div")[0];
        input = div.getElementsByTagName("input")[0];
        txtValue = input.placeholder;
        if (txtValue.toUpperCase().indexOf(filter) > -1) {
            li[i].style.display = "";
        } else {
            li[i].style.display = "none";
        }
    }
}

function clickFunction(id, val) {
    if (document.getElementById(id).value.length === 0) {
        document.getElementById(id).value = val;
    }
}

function change(id) {
    var bool = false;
    var input, ul, li, divs, form, i, j;
    ul = document.getElementById("myUL");
    li = ul.getElementsByTagName('li');

    for (i = 0; i < li.length; i++) {
        form = li[i].getElementsByTagName("form")[0];
        divs =  form.getElementsByTagName("div");
        for (j= 0; j < divs.length; j++) {
            input = divs[j].getElementsByTagName("input")[0];
            if (input !== undefined) {
                if (input.value.length > 0) {
                    bool = true;
                    break;
                }
            }
        }
    }

    var btn = "saveBtn" + id;

    if (bool) {
        document.getElementById(btn).style.display = "block";
    } else {
        document.getElementById(btn).style.display = "none";
    }
}

function changeProject(id) {
    var bool = false;
    var input, ul, li, divs, form, i, j;
    ul = document.getElementById("myUL");
    li = ul.getElementsByTagName('li');

    for (i = 0; i < li.length; i++) {
        form = li[i].getElementsByTagName("form")[0];
        divs =  form.getElementsByTagName("div");
        for (j= 0; j < divs.length; j++) {
            input = divs[j].getElementsByTagName("input")[0];
            if (input !== undefined) {
                if (input.value.length > 0) {
                    bool = true;
                    break;
                }
            }
        }
    }

    var txtAreaName = "updateDescription" + id;
    var txtArea = document.getElementById(txtAreaName);

    if (!bool && txtArea.value.length > 0) {
        bool = true;
    }

    var btn = "saveBtn" + id;

    if (bool) {
        document.getElementById(btn).style.display = "block";
    } else {
        document.getElementById(btn).style.display = "none";
    }
}

function changeDetails() {
    var i;
    var input = document.getElementsByTagName('input');
    var textarea = document.getElementById('bio');
    var bool = false;

    for (i = 0; i < input.length; i++) {
        val = input[i].value
        if (val.length > 0 && (input[i].name !== "csrfmiddlewaretoken")) {
            bool = true;
            if (input[i].name === 'file') {
                console.log(name);
                console.log($('#file')[0].files[0]);
            }
             break;
        }
    }

    if (!bool && textarea.value.length > 0) {
        bool = true;
    }

    if (bool) {
        document.getElementById("saveBtn").style.display = "block";
    } else {
        document.getElementById("saveBtn").style.display = "none";
    }
}