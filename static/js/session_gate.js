/*
 * Session gate: send the browser to /login when a request comes back 401.
 *
 * The appliance uses a long-lived session cookie, so this should be rare. It
 * exists so that removing the old "trust any localhost" bypass cannot leave the
 * UI showing empty panels with no explanation.
 */
(function () {
  var redirecting = false;

  function goToLogin() {
    if (redirecting) return;
    redirecting = true;
    window.location.href = "/login";
  }

  if (typeof window.fetch === "function") {
    var originalFetch = window.fetch.bind(window);
    window.fetch = function () {
      var args = arguments;
      return originalFetch.apply(null, args).then(function (response) {
        if (response && response.status === 401) {
          goToLogin();
        }
        return response;
      });
    };
  }

  if (window.XMLHttpRequest && window.XMLHttpRequest.prototype) {
    var originalOpen = window.XMLHttpRequest.prototype.open;
    window.XMLHttpRequest.prototype.open = function () {
      this.addEventListener("load", function () {
        if (this.status === 401) {
          goToLogin();
        }
      });
      return originalOpen.apply(this, arguments);
    };
  }
})();
