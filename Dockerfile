# Image minimale : build statique musl, exécution depuis scratch.
# L'outil est hors ligne par conception (§13 : lecture seule) — aucune
# dépendance d'exécution, pas de certificats, pas de shell.

FROM rust:1-alpine AS build
RUN apk add --no-cache musl-dev binutils
WORKDIR /src
COPY . .
RUN cargo build --release --locked -p calque-cli \
    && strip target/release/calque

FROM scratch
COPY --from=build /src/target/release/calque /calque
# Le répertoire de travail : monter ses configurations ici
# (docker run -v "$PWD:/work" …). Le projet .calque/ y est écrit.
WORKDIR /work
ENTRYPOINT ["/calque"]
CMD ["--help"]
