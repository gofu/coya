var $ = document.getElementById.bind(document);

function sendRequest(method, path, contentType, data) {
    return new Promise(function (resolve, reject) {
        try {
            var xhr = new XMLHttpRequest();
            xhr.addEventListener('error', function (err) {
                reject({ok: false, error: "Request error."});
            });
            xhr.addEventListener('abort', function (err) {
                reject({ok: false, error: "Request aborted."});
            });
            xhr.addEventListener('load', function (e) {
                try {
                    var result = JSON.parse(e.target.responseText);
                } catch (e) {
                    reject({ok: false, error: "Invalid JSON received."});
                    return;
                }
                if (!result.ok) {
                    reject(result);
                    return;
                }
                resolve(result);
            });
            xhr.open(method, path);
            if (contentType) {
                xhr.setRequestHeader('Content-Type', contentType);
            }
            if (data) {
                xhr.send(data);
            } else {
                xhr.send();
            }
        } catch (e) {
            reject(e);
        }
    });
}

/**
 * @param el {Element}
 */
function showDialog(el) {
    function onKeyUp(e) {
        if (e.key !== "Escape") {
            return;
        }
        hideDialog();
    }

    function onCloseClick(e) {
        e.preventDefault();
        hideDialog();
    }

    function onOverlayClick(e) {
        if (e.target !== el) {
            return;
        }
        hideDialog();
    }

    var closes = el.getElementsByClassName('close');

    function hideDialog() {
        document.removeEventListener('keyup', onKeyUp);
        el.removeEventListener('click', onOverlayClick);
        for (var i = 0; i < closes.length; i++) {
            closes.item(i).removeEventListener('click', onCloseClick);
        }
        el.style.display = null;
    }

    document.addEventListener('keyup', onKeyUp);
    el.addEventListener('click', onOverlayClick);
    for (var i = 0; i < closes.length; i++) {
        closes.item(i).addEventListener('click', onCloseClick);
    }
    el.style.display = 'flex';

    return hideDialog;
}

function main() {
    var hamburger = $('menu-toggle');
    var sidebar = $('sidebar');
    var activeClass = 'is-active';
    var menuClass = 'menu-closed';
    hamburger.addEventListener('click', function() {
        if (hamburger.classList.contains(activeClass)) {
            hamburger.classList.remove(activeClass);
            sidebar.classList.remove(activeClass);
        } else {
            hamburger.classList.add(activeClass);
            sidebar.classList.add(activeClass);
        }
    });

    var loginDialog = $('login-dialog');

    $('copyright').addEventListener('click', function (e) {
        e.preventDefault();
        showDialog(loginDialog);
    });

    var carousel = $('home-carousel');
    if (carousel && carousel.dataset.carousel) {
        var images = carousel.dataset.carousel.split(',');
        carousel.style.backgroundImage ='url('+images[0]+')';
    }

    var loginError = $('login-error');

    function loginFormError(err) {
        if (!err) {
            loginError.style.display = 'none';
            return;
        }
        loginError.style.display = 'block';
        loginError.innerText = err;
    }

    loginFormError();

    var loginForm = $('login-form');

    function loginFormLock(lock) {
        loginForm.email.disabled = lock;
        loginForm.password.disabled = lock;
        loginForm.login.disabled = lock;
    }

    loginForm.addEventListener('submit', function (e) {
        e.preventDefault();
        loginFormLock(true);
        var data = JSON.stringify({email: loginForm.email.value, password: loginForm.password.value});
        sendRequest("POST", "/login", "application/json", data)
            .then(function () {
                loginFormError();
                document.location.reload();
            }, function (reason) {
                loginFormError(reason.error);
            }).then(function () {
            loginFormLock(false);
        });
    });

    var contactForm = $('contact-form');
    if (contactForm) {
        function contactFormLock(lock) {
            contactForm.email.disabled = lock;
            contactForm.message.disabled = lock;
            contactForm.send.disabled = lock;
        }

        var contactError = $('contact-error');
        var contactOK = $('contact-ok');

        function contactFormError(err) {
            if (!err) {
                contactOK.style.display = 'block';
                contactError.style.display = 'none';
                return;
            }
            contactOK.style.display = 'none';
            contactError.style.display = 'block';
            contactError.innerText = err;
        }

        contactForm.addEventListener('submit', function (e) {
            e.preventDefault();
            var data = JSON.stringify({email: contactForm.email.value, message: contactForm.message.value});
            contactFormLock(true);
            sendRequest("POST", "/contact", "application/json", data)
                .then(function () {
                    contactFormError();
                }, function (reason) {
                    contactFormLock(false);
                    contactFormError(reason.error);
                }).then(function () {
                loginFormLock(false);
            });
        })
    }

    var portfolioForm = $('portfolio-form');
    if (portfolioForm) {
        function portfolioFormLock(lock) {
            portfolioForm.title.disabled = lock;
            portfolioForm.image.disabled = lock;
            portfolioForm.send.disabled = lock;
        }

        var portfolioError = $('portfolio-error');
        var portfolioOK = $('portfolio-ok');

        function portfolioFormError(err) {
            if (!err) {
                portfolioOK.style.display = 'block';
                portfolioError.style.display = 'none';
                return;
            }
            portfolioOK.style.display = 'none';
            portfolioError.style.display = 'block';
            portfolioError.innerText = err;
        }

        portfolioForm.addEventListener('submit', function (e) {
            e.preventDefault();
            var data = new FormData();
            data.append("title", portfolioForm.title.value);
            for (var i = 0; i < portfolioForm.image.files.length; i++) {
                data.append("image", portfolioForm.image.files[i]);
            }
            portfolioFormLock(true);
            sendRequest("POST", "/admin/portfolio", '', data)
                .then(function () {
                    document.location.reload();
                }, function (reason) {
                    portfolioFormLock(false);
                    portfolioFormError(reason.error);
                }).then(function () {
                portfolioFormLock(false);
            });
        });


        function onDeleteClick(e) {
            var id = e.target.dataset.id;
            if (!id) {
                return;
            }
            e.preventDefault();
            sendRequest("DELETE", "/admin/portfolio?id=" + id)
                .then(function () {
                    var remove = document.getElementsByClassName(e.target.dataset.remove)
                    for (var i = 0; i < remove.length; i++) {
                        remove.item(i).remove();
                    }
                });
        }

        function onChooseCheck(e) {
            var id = e.target.dataset.id;
            if (!id) {
                return;
            }
            sendRequest("PUT", "/admin/portfolio?id=" + id + "&field=chosen", 'application/json', JSON.stringify({chosen: e.target.checked}));
        }

        var deletes = document.getElementsByClassName('delete-portfolio');
        for (var i = 0; i < deletes.length; i++) {
            deletes.item(i).addEventListener('click', onDeleteClick);
        }

        var chosens = document.getElementsByClassName('choose-portfolio');
        for (var i = 0; i < chosens.length; i++) {
            var el = chosens.item(i);
            if (el.tagName !== 'INPUT' || el.type !== 'checkbox') {
                continue;
            }
            el.addEventListener('change', onChooseCheck);
        }
    }
}

main();
