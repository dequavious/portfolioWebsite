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

const sr1 = ScrollReveal({
    origin:"top",
    distance:"-80px",
    duration:2000,
    reset:false,
});

sr1.reveal (
    `
    .about,.skills,.portfolio
    `,{
        interval:300,
    }
);

const sr2 = ScrollReveal({
    origin:"right",
    distance:"50%",
    duration:3000,
    reset:false,
});

sr2.reveal (
    `
    #spring1,#spring2
    `
);

const sr3 = ScrollReveal({
    origin:"left",
    distance:"50%",
    duration:3000,
    reset:false,
});

sr3.reveal (
    `
    #spring1L,#spring2L
    `
);