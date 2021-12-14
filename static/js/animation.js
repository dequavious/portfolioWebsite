// const sr = ScrollReveal({
//     origin:"top",
//     distance:"-80px",
//     duration:2000,
//     reset:false,
// });
//
// sr.reveal (
//     `
//     .hero, .about, .skills, .portfolio, .programming, .more-info, .contact, .footer
//     `, {
//         interval:300,
//     }
// )

const sr2 = ScrollReveal({
    origin:"right",
    distance:"50%",
    duration:3000,
    reset:false,
});

sr2.reveal (
    `
    #spring1, #spring3, #spring5, #spring7,
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
    #spring2, #spring4, #spring6,
    `
);