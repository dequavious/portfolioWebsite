const sr = ScrollReveal({
    origin:"top",
    distance:"-80px",
    duration:2000,
    reset:true,
});

sr.reveal (
    `
    .hero
    `,{
        interval:300,
    }
);

const sectionsArray = [
    document.querySelector('#about'),
    document.querySelector('#skills'),
    document.querySelector('#portfolio'),
    document.querySelector('#programming'),
    document.querySelector('#info'),
    document.querySelector('#contact')
];

const sr1 = ScrollReveal({
    origin:"top",
    distance:"-80px",
    duration:2000,
    reset:false,
});

sr1.reveal(sectionsArray,{interval:300});

const springArrayR = [
    document.querySelector('#spring1'),
    document.querySelector('#spring2'),
    document.querySelector('#spring3'),
    document.querySelector('#spring4')
];

const sr2 = ScrollReveal({
    origin:"right",
    distance:"50%",
    reset:false
});

sr2.reveal(springArrayR);

const springArrayL = [
    document.querySelector('#spring1L'),
    document.querySelector('#spring2L'),
    document.querySelector('#spring3L')
];

const sr3 = ScrollReveal({
    origin:"left",
    distance:"50%",
    reset:false
});

sr3.reveal(springArrayL);