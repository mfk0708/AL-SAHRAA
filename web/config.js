/* Contract Assessment Tools – front-end configuration.
   api: where the browser reaches the back end. Keep '/api' and let the web server forward /api/ to the
   back end (same origin is required: session cookies are SameSite=Strict). */
window.CAT_SERVER = window.CAT_SERVER || { api: 'https://al-sahraa.onrender.com' };
