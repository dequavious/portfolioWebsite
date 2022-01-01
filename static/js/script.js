n =  new Date();
y = n.getFullYear();
document.getElementById("date").innerHTML = "<i class=\"fa fa-copyright\"></i> " + y +  ", All rights reserved."

const scrollToTop = document.querySelector(".scrollToTop");
scrollToTop.addEventListener("click", ()=>{
    window.scrollTo({top:0});
});
window.addEventListener("scroll", ()=>{
    if (window.pageYOffset > 100) {
        document.querySelector(".toggle.open .menu-btn__burger").style.position = "fixed";
        scrollToTop.style.display = "block";
    } else {
        document.querySelector(".toggle.open .menu-btn__burger").style.position = "relative";
        scrollToTop.style.display = "none";
    }
});

let menuOpen = false;
const html = document.querySelector("html");
const responsiveNavBar = document.querySelector(".responsive__navbar");
const responsiveToggle = document.querySelector(".toggle");
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
        document.querySelector(".menu-btn__burger").style.position = "relative";
      }
});

html.addEventListener("click", ()=>{
    document.querySelector(".menu-btn__burger").style.position = "relative";
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