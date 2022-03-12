n =  new Date();
y = n.getFullYear();
document.getElementById("date").innerHTML = "<i class=\"fa fa-copyright\"></i> " + y +  ", All rights reserved."

var prevScrollpos = window.pageYOffset;
window.onscroll = function() {
var currentScrollPos = window.pageYOffset;
  if (prevScrollpos > currentScrollPos) {
    document.getElementById("navbar").style.top = "0";
  } else {
    document.getElementById("navbar").style.top = "-105px";
    selectFunction();
    closeResponsive();
  }
  prevScrollpos = currentScrollPos;
}

function closeNavbar() {
      setTimeout(
    function() {
        document.getElementById("navbar").style.top = "-105px";
    }, 750);
}

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
const myDropdown = document.getElementById("myDropdown");
const myDropdownResponsive = document.getElementById("myDropdownResponsive");
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

html.addEventListener("click", function(e){
    menuBurger.style.position = "relative";
    responsiveToggle.classList.remove('open');
    responsiveNavBar.classList.remove("show");
    menuOpen = false;
    selectFunctionResponsive();
    var targetText  = $(e.target).text();
    if (!targetText.startsWith("Documents") && targetText !== "") {
        selectFunction();
    }
});

function closeResponsive() {
    responsiveToggle.classList.remove('open');
    responsiveNavBar.classList.remove("show");
    menuOpen = false;
}

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
  if (myDropdown.style.display==="none") {
      myDropdown.style.display= "block";
  } else {
      myDropdown.style.display= "none";
  }
}

function selectFunction() {
    myDropdown.style.display= "none";
}

function toggleFunctionResponsive() {
  if (myDropdownResponsive.style.display==="none") {
      myDropdownResponsive.style.display = "block";
  } else {
      myDropdownResponsive.style.display = "none";
  }
}

function selectFunctionResponsive() {
    myDropdownResponsive.style.display = "none";
}

function openProject(evt, projName, projLink) {
    var i, tabcontent, tablinks, activeProj
    tabcontent = document.getElementsByClassName("tabcontent");
    for (i = 0; i < tabcontent.length; i++) {
        tabcontent[i].style.display = "none";
    }
    tablinks = document.getElementsByClassName("tablinks");
    for (i = 0; i < tablinks.length; i++) {
        tablinks[i].className = tablinks[i].className.replace(" active", "");
        tablinks[i].innerHTML = tablinks[i].name;
    }
    activeProj = document.getElementById(projName);
    activeProj.style.display = "block";
    evt.currentTarget.className += " active";
    projLink.innerHTML = "<i class=\"fa fa-circle\"></i> " + projLink.name;
}

// Get the element with id="defaultOpen" and click on it
document.getElementById("defaultOpen").click();

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