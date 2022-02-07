n =  new Date();
y = n.getFullYear();
document.getElementById("date").innerHTML = "<i class=\"fa fa-copyright\"></i> " + y +  ", All rights reserved."

const responsiveToggle = document.querySelector(".toggle");
const menuBurger = document.querySelector(".menu-btn__burger");
const scrollToTop = document.querySelector(".scrollToTop");
scrollToTop.style.display = "none";
scrollToTop.addEventListener("click", ()=>{
    window.scrollTo({top:0});
});
window.addEventListener("scroll", ()=>{
    if (window.pageYOffset > 100) {
         scrollToTop.style.display = "block";
         if (responsiveToggle.classList.contains("open")) {
             menuBurger.style.position = "fixed";
         }
    } else {
        scrollToTop.style.display = "none";
        if (responsiveToggle.classList.contains("open")) {
            menuBurger.style.position = "relative";
        }
    }
});

let menuOpen = false;
const html = document.querySelector("html");
const responsiveNavBar = document.querySelector(".responsive__navbar");
responsiveNavBar.addEventListener("click", (e)=>e.stopPropagation());

responsiveToggle.addEventListener("click", (e)=>{
    e.stopPropagation();
      if(!menuOpen) {
        responsiveToggle.classList.add('open');
        responsiveNavBar.classList.toggle("show");
        menuOpen = true;
      } else {
        responsiveToggle.classList.remove('open');
        responsiveNavBar.classList.remove("show");
        menuOpen = false;
        selectFunctionResponsive();
        menuBurger.style.position = "relative";
      }
});

html.addEventListener("click", ()=>{
    menuBurger.style.position = "relative";
    responsiveToggle.classList.remove('open');
    responsiveNavBar.classList.remove("show");
    menuOpen = false;
    selectFunctionResponsive();
});

const navLinks = document.querySelectorAll(".nav__link");
navLinks.forEach((link)=>{
    link.addEventListener("click", ()=>{
        responsiveToggle.classList.remove('open');
        responsiveNavBar.classList.remove("show");
        menuOpen = false;
        selectFunctionResponsive();
        document.querySelector(".menu-btn__burger").style.position = "relative";
    });
});

function toggleFunction() {
  if (document.getElementById("myDropdown").style.display==="none") {
      document.getElementById("myDropdown").style.display= "block";
  } else {
      document.getElementById("myDropdown").style.display= "none";
  }
}

function selectFunction() {
    document.getElementById("myDropdown").style.display= "none";
}

function toggleFunctionResponsive() {
  if (document.getElementById("myDropdownResponsive").style.display==="none") {
      document.getElementById("myDropdownResponsive").style.display = "block";
  } else {
      document.getElementById("myDropdownResponsive").style.display = "none";
  }
}

function selectFunctionResponsive() {
    document.getElementById("myDropdownResponsive").style.display = "none";
}

function openProject(evt, projName, projLink, projTitle) {
    var i, tabcontent, tablinks;
    tabcontent = document.getElementsByClassName("tabcontent");
    for (i = 0; i < tabcontent.length; i++) {
        tabcontent[i].style.display = "none";
    }
    tablinks = document.getElementsByClassName("tablinks");
    for (i = 0; i < tablinks.length; i++) {
        tablinks[i].className = tablinks[i].className.replace(" active", "");
        tablinks[i].innerHTML = tablinks[i].name;
    }
    document.getElementById(projName).style.display = "block";
    evt.currentTarget.className += " active";

    document.getElementById(projLink).innerHTML = "<i class=\"fas fa-terminal\"></i> " + projTitle;
}

// Get the element with id="defaultOpen" and click on it
document.getElementById("defaultOpen1").click();

function breakPt(x) {
    var i, tabcontent, port_cont;
    tabcontent = document.getElementsByClassName("tabcontent");
    port_cont = document.getElementsByClassName("portfolio__container");
    if (x.matches) {
        for (i = 0; i < tabcontent.length; i++) {
            tabcontent[i].style.display = "none";
        }
        for (i = 0; i < port_cont.length; i++) {
            port_cont[i].style.display = "grid";
        }
    } else {
        for (i = 0; i < port_cont.length; i++) {
            port_cont[i].style.display = "none";
        }
        document.getElementById("defaultOpen").click();
    }
}

var x = window.matchMedia("(max-width: 445px)");
breakPt(x);
x.addListener(breakPt);