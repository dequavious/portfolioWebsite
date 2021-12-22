const scrollToTop = document.querySelector(".scrollToTop");
scrollToTop.addEventListener("click", ()=>{
    window.scrollTo({top:0});
});
window.addEventListener("scroll", ()=>{
    window.pageYOffset > 100 ?
        (scrollToTop.style.display = "block") :
        (scrollToTop.style.display = "none");
});

const html = document.querySelector("html");
const responsiveNavBar = document.querySelector(".responsive__navbar");
const responsiveToggle = document.querySelector(".toggle");
responsiveNavBar.addEventListener("click", (e)=>e.stopPropagation());

responsiveToggle.addEventListener("click", (e)=>{
    e.stopPropagation();
    responsiveNavBar.classList.toggle("show");
});

html.addEventListener("click", ()=>responsiveNavBar.classList.remove("show"));

const navLinks = document.querySelectorAll(".nav__link");
navLinks.forEach((link)=>{
    link.addEventListener("click", ()=>{
        responsiveNavBar.classList.remove("show");
        selectFunctionResponsive();
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