  root {{DOCROOT}};
  index index.html index.htm;
  location ~ /\. { deny all; }
  location ~* \.(?:env|log|sql|bak|ini|sh|git|ya?ml|lock|dist|swp)$ { deny all; }
  location / { try_files $uri $uri/ =404; }
