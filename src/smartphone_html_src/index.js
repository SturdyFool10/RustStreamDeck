function closeMenu() {
    $('#menu').animate({
        "left": "-25%"
    }, 250);
    $("#main-content").animate({
        "left": "0%"
    }, 250).animate({
        "background-color": "var(--pageBG)"
    }, 350);
}
$(document).ready(function() {
    $('#menu').animate({
        "left": "-25%"
    }, 1);
    var classMap = {
        "Servers": ".servers",
        "Configuration": ".config",
        "Stats": ".stat"
    }
    $("#menu ul li a").click(function(e) {
        $(".active").toggleClass("active");
        $(e.target.parentElement).toggleClass("active");
        $(".page").hide();
        $(".grad").show();
        $(classMap[e.target.innerHTML]).show();
    })
    $($("#menu ul li")[0]).toggleClass("active");
    $(".page").hide();
    $(".servers").show();
    var menuOpen = false;
    $('#menu-icon').click(function() {
        if (menuOpen) {
            closeMenu();
            $(".overlay").fadeTo(350, 0.0, "linear", function() {
                $(".grad").hide();
            });
        } else {
            $('#menu').animate({
                "left": "0%"
            }, 250);
            $("#main-content").animate({
                "left": "25%",
            }, 250)
            setTimeout(function() {
                $(".grad").show();
                $(".overlay").fadeTo(350, 1.0, "linear");
            }, 100)
        }
        console.log("menu clicked");
        setTimeout(function() {
            menuOpen = !menuOpen;
        }, 250);
    });
    $("#main-content").hover(function() {
        if (menuOpen) {
            closeMenu();
            $(".overlay").fadeTo(350, 0.0, "linear", function() {
                $(".grad").hide();
            });
        }
        menuOpen = false;
    });
    var canvas = $(" < canvas class = \"overlay\" width=" + 800 + " height=" + 2 + "></canvas>").appendTo($(".grad"))[0]
    var ctx = canvas.getContext("2d");

    function handleCanvas() {
        if (window.innerWidth != canvas.width || (window.innerHeight != canvas.height)) {
            $(canvas).remove();
            canvas = $(" < canvas class = \"overlay\" width=" + window.innerWidth + " height=" + window.innerHeight + "></canvas>").appendTo($(".grad"))[0]
            ctx = canvas.getContext("2d");
            var bg = "rgba(14, 14, 14, 0.45)"
            var highlight = "rgba(162, 0, 255, 1)"
            var grad = ctx.createLinearGradient(0, 0, canvas.width, 0);
            grad.addColorStop(0, highlight);
            grad.addColorStop(0.05, bg);
            grad.addColorStop(1, bg);
            ctx.fillStyle = grad;
            ctx.fillRect(0, 0, canvas.width, canvas.height);
        }
        requestAnimationFrame(handleCanvas);
    }
    handleCanvas();
});