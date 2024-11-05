# Build stage
#FROM golang:1.21 AS build
# Use the official Golang image as the base image
FROM golang:1.20-alpine AS build

# Set the Current Working Directory inside the container
WORKDIR /literary-lions
COPY go.mod go.sum ./
# Download all dependencies. Dependencies will be cached if the go.mod and go.sum files are not changed
# RUN go mod download

RUN apk add --no-cache gcc musl-dev sqlite-libs && go mod download

# Copy the source code into the container
COPY . .

# Enable CGO
ENV CGO_ENABLED=1
# Install build dependencies for sqlite3
# RUN apk add --no-cache gcc musl-dev && go build -o main .
# Build the execute file
RUN go build -o main .

# Final stage
FROM alpine:latest
# Set the Current Working Directory inside the container
WORKDIR /literary-lions
COPY --from=build /literary-lions/main ./main
COPY --from=build /literary-lions/views ./views
COPY --from=build /literary-lions/static ./static
COPY --from=build /literary-lions/forum.db ./forum.db

# Install runtime dependencies (if still needed)
RUN apk add --no-cache sqlite-libs sqlite

# Expose port 8080 to the outside world
EXPOSE 8080
# Run the executable
CMD ["./main"]
