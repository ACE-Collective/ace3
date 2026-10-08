// How a TP/FP verdict looks, wherever one is shown (docs/SVS.md, Part 1): the verdict chips on the
// alert page (detection_verdicts.js) and the labels and detection verdicts of SVS samples
// (signatures_samples.js). A verdict counts as a disposition, so it is one of the few things the
// GUI shows as a badge.

var aceVerdicts = (function() {
    "use strict";

    const SOURCE_LABELS = {
        explicit: "explicit",
        inherited_single: "inherited",
        inherited_multi: "unconfirmed",
    };

    const SOURCE_TITLES = {
        explicit: "set by an analyst",
        inherited_single: "inherited from the alert's disposition",
        inherited_multi: "inherited from the alert's disposition, on an alert where several signatures fired; nobody has confirmed it",
    };

    function chip(text, css, title) {
        const element = document.createElement("span");
        element.className = "badge border border-dark ms-1 " + css;
        element.style.fontSize = "0.75rem";
        element.textContent = text;
        if (title) {
            element.title = title;
        }
        return element;
    }

    function css(verdict) {
        return verdict === "fp" ? "text-bg-success" : "text-bg-warning";
    }

    // a verdict and the source it comes from: "TP · inherited"
    function badge(verdict, source) {
        return chip(verdict.toUpperCase() + " · " + SOURCE_LABELS[source], css(verdict), SOURCE_TITLES[source]);
    }

    return {
        SOURCE_LABELS: SOURCE_LABELS,
        SOURCE_TITLES: SOURCE_TITLES,
        chip: chip,
        css: css,
        badge: badge,
    };
})();
