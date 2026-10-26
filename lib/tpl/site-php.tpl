  root {{DOCROOT}};
  index index.php index.html;

  location ~ /\.(?!well-known) { deny all; }
  location ~* ^/(?:wp-content/(?:uploads|cache|upgrade|backup[^/]*)|uploads|storage)/.*\.(?:php[0-9]?|phtml|phar)$ { deny all; }
  location ~* \.(?:env|log|sql|bak|ini|sh|git|ya?ml|lock|dist|swp)$ { deny all; }
  location ~* /(?:composer\.(?:json|lock)|package(?:-lock)?\.json)$ { deny all; }
  location ~* \.(?:css|js|mjs|jpe?g|png|gif|webp|avif|svg|ico|woff2?|ttf|otf|eot|mp4|webm|pdf)$ {
    expires 30d;
    access_log off;
    try_files $uri /index.php?$query_string;
  }
  location / { try_files $uri $uri/ /index.php?$query_string; }
  location ~ \.php$ {
    include snippets/fastcgi-php.conf;
    fastcgi_pass unix:/run/php/{{USER}}.sock;
    fastcgi_read_timeout {{TIMEOUT}}s;
    fastcgi_hide_header X-Powered-By;
  }
