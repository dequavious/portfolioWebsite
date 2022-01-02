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

function searchTechnology() {
    var input, filter, ul, li, divs, div, form, i, j, k, label, txtValue1, txtValue2, txtValue3, values, typeValue, confidenceValue;
    values = document.getElementsByName('filterType');
    typeValue = getSelectedValue(values);
    values = document.getElementsByName('filterConfidence');
    confidenceValue = getSelectedValue(values);
    input = document.getElementById('myInput');
    filter = input.value.toUpperCase();
    ul = document.getElementById("myUL");
    li = ul.getElementsByTagName('li');

    for (i = 0; i < li.length; i++) {
        form = li[i].getElementsByTagName("form")[0];
        div =  form.getElementsByTagName("div")[0];
        input = div.getElementsByTagName("input")[0];
        txtValue1 = input.placeholder;
        div =  form.getElementsByTagName("div")[1];
        divs =  div.getElementsByTagName("div");
        for (j = 0; j < divs.length; j++) {
            label = divs[j].getElementsByTagName("label")[0];
            input = label.getElementsByTagName("input")[0];
            if (input.checked) {
                txtValue2 = input.value;
                break;
            }
        }
        div =  form.getElementsByTagName("div")[6];
        divs =  div.getElementsByTagName("div");
        for (k = 0; k < divs.length; k++) {
            label = divs[k].getElementsByTagName("label")[0];
            input = label.getElementsByTagName("input")[0];
            if (input.checked) {
                txtValue3 = input.value;
                break;
            }
        }
        if (txtValue1.toUpperCase().indexOf(filter) > -1) {
            if ((typeValue === "All") && (confidenceValue === "All")) {
                li[i].style.display = "";
            } else if (!((typeValue === "All") || (confidenceValue === "All"))) {
                if ((typeValue === txtValue2) && (confidenceValue === txtValue3)) {
                    li[i].style.display = "";
                } else {
                    li[i].style.display = "none";
                }
            } else if (confidenceValue === "All") {
                if (typeValue === txtValue2) {
                    li[i].style.display = "";
                } else {
                    li[i].style.display = "none";
                }
            } else if (typeValue === "All") {
                if (confidenceValue === txtValue3) {
                    li[i].style.display = "";
                } else {
                    li[i].style.display = "none";
                }
            } else {
                li[i].style.display = "none";
            }
        } else {
            li[i].style.display = "none";
        }
    }
}

function getSelectedValue(values) {
    var i;
    for (i = 0; i < values.length; i++) {
        if (values[i].checked) {
            return values[i].value;
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

function changeTech(id, type, confidence) {
    var bool = false;
    var input, ul, li, div, divs, form, label, i, j, k;
    ul = document.getElementById("myUL");
    li = ul.getElementsByTagName('li');

    for (i = 0; i < li.length; i++) {
        form = li[i].getElementsByTagName("form")[0];
        divs =  form.getElementsByTagName("div");
        for (j= 0; j < divs.length; j++) {
            input = divs[j].getElementsByTagName("input")[0];
            if ((input !== undefined) && (input.type !== "radio")) {
                if (input.value.length > 0) {
                    bool = true;
                    break;
                }
            }
        }
    }

    div =  form.getElementsByTagName("div")[1];
    divs =  div.getElementsByTagName("div");
    for (k = 0; k < divs.length; k++) {
        label = divs[k].getElementsByTagName("label")[0];
        input = label.getElementsByTagName("input")[0];
        if (input.checked && (input.value !== type)) {
            bool = true;
            break;
        }
    }

    div =  form.getElementsByTagName("div")[6];
    divs =  div.getElementsByTagName("div");
    for (k = 0; k < divs.length; k++) {
        label = divs[k].getElementsByTagName("label")[0];
        input = label.getElementsByTagName("input")[0];
        if (input.checked && (input.value !== confidence)) {
            bool = true;
            break;
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
    var textarea1 = document.getElementById('bio');
    var textarea2 = document.getElementById('quote');
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

    if (!bool && ((textarea1.value.length > 0) || (textarea2.value.length > 0))) {
        bool = true;
    }

    if (bool) {
        document.getElementById("saveBtn").style.display = "block";
    } else {
        document.getElementById("saveBtn").style.display = "none";
    }
}