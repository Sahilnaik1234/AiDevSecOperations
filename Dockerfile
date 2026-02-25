# HIPAA Violation: Using an old, unmaintained image
FROM node:10.15.3

# HIPAA Violation: Running as root
USER root

WORKDIR /app

# HIPAA Violation: Exposing unencrypted ports (HTTP)
EXPOSE 80

# HIPAA Violation: Copying sensitive credentials into the image
COPY .docker-env .env

CMD ["npm", "start"]
