# Use the official Golang image as a parent image
FROM golang:1.19 AS builder

# Set the working directory inside the container
WORKDIR /app

# Copy the Go code into the container
COPY . .

# Initialize a new module or migrate old ones
RUN go mod init app || echo "Module already initialized"

# Fetch and tidy up the dependencies
RUN go mod tidy

# Build the Go app
RUN CGO_ENABLED=0 GOOS=linux go build -o main .

# Use a lightweight alpine image for the final image
FROM alpine:latest

# Expose port 3050
EXPOSE 3050

# Copy the binary from the builder stage
COPY --from=builder /app/main /app/

# Specify the command to run on container start
CMD ["/app/main"]
