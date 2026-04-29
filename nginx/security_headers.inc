add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
add_header X-Content-Type-Options "nosniff" always;
add_header X-Frame-Options "SAMEORIGIN" always;
add_header X-XSS-Protection "1; mode=block" always;
add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline' https://www.googletagmanager.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; img-src 'self' data: https://img.shields.io https://www.googletagmanager.com https://www.google-analytics.com; connect-src 'self' https://www.google-analytics.com; frame-ancestors 'self'; object-src 'none';" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
