

# __Literary Lions Forum__

## Introduction
The Literary Lions Forum is designed to help book club enthusiasts to engage in meaningful discussions, share insights, and explore deeper literary themes. Users can create posts, leave comments, categorize discussions, like/dislike content, and filter posts. The forum utilized SQLite as the database, and is containerized using Docker.

<img width="1696" height="814" alt="image" src="https://github.com/user-attachments/assets/7406c980-fa90-48b8-a35a-9c41be8f18bc" />


## Features

### User Registration and Authentication:

- Users can register with an email, username, and password.
- Login is based on email and password.
- Session management is handled using cookies with expiration time.

#### Passwords are stored securely in the database using BCrypt encryption. Sessions are managed using UUIDs, providing secure and unique identification for user sessions.

### Database interaction:
You can find a database schema with relationships between entities of the structure in the ERD Diagram ![ERD Diagram](/static/images/ERD.jpg "Entity Relationship Diagram") 

User registration data is stored in forum.db.
Interaction with the database is carried out through SQL queries SELECT, CREATE and INSERT.

#### Database Schema
consists of the following tables:
- Users: Stores user information (email, username, password hash).
- Posts: Contains posts made by users.
- Comments: Stores comments on posts.
- Categories: Defines categories for posts (Literature, Poetry, Non-fiction, Short Stories).
- Likes_dislikes: Stores likes/dislikes on posts.
- Comment_likes: Stores likes/dislikes on comments.
- Sessions: Stores unique session identifier, user_id associated with the session and the session expiration time.

### Post and Comment System:

Only registered users can create posts and comments.
Posts can be associated with specific categories (Literature, Poetry, Non-fiction, Short Stories).

### Liking/Disliking system

Registered users can like or dislike posts and comments.
The number of likes/dislikes, posts and comments are visible to all users, providing instant feedback on the popularity of discussions.

### Technologies & Prerequisites
- Backend: Go (Golang 1.20 or later)
- Database: SQLite with go-sqlite3 driver
- Frontend: HTML, CSS, Go
- Containerization: Docker

## Getting Started

### Installation
Clone the repository:
```
git clone https://[repo link]
cd literary-lions
```

Install Go dependencies if necessary:
``` 
go mod tidy
```

Initialize SQLite database regarding https://pkg.go.dev/github.com/mattn/go-sqlite3

### Dockerization
Follow the steps below to set up Docker, build the Docker image, run the container, and maintains a clean environment. 

1. #### Install Docker
Before you begin, ensure that Docker is installed on your machine. Download Docker Desktop from [the Docker website](https://docs.docker.com/get-started/get-docker/). __If you use WSL__: https://docs.docker.com/desktop/wsl/.

* __For Windows__: After installation, start Docker Desktop and ensure it is running.
* __For macOS__: Open the downloaded .dmg file and drag Docker to your Applications folder, launch and ensure it is running. 
* __For Linux__: Follow the official Docker installation guide for your distribution: https://docs.docker.com/desktop/install/linux/

Start the Docker service:
```
sudo systemctl start docker
```
Ensure Docker is running:
```
systemctl status docker
```
2. #### Navigate to the project directory and build the Docker image:
```
docker build -t lions-forum-image .
```
or
```
DOCKER_BUILDKIT=0 docker build --no-cache -t lions-forum-image . 
```
If you got "ERROR: BuildKit is enabled but the buildx component is missing or broken."

3. #### Start the container using the built image:
```
docker run -d -p 8080:8080 -v lions_volume:/literary-lions/ --name lions-forum lions-forum-image

```
This command runs a container named <my-container> from the <my-image>,  mapping port 8080 on the host to port 8080 on the container.
The application will be available at http://localhost:8080.

4. #### Verify Container Operation. To verify that the container is running:
```
docker ps
``` 
Lists all running containers. 
```
docker images
```
Shows all images. You can check the logs of the running container:
```
docker logs lions-forum
```
5. #### To keep your Docker environment clean, remove unused objects.
To stop container:
```
docker stop container_ID
```
Remove stopped containers: 
```
docker rm -f <container_name_or_id>
``` 
Remove image: 
```
docker rmi <image_name_or_id>
docker image prune -a -f
``` 
for all unused images.

Remove unused volumes:
```
docker volume prune -f
```
Remove unused networks: 
```
docker network prune -f
```
Full system cleanup (optional): 
```
docker system prune -a --volumes -f
```
This command removes all unused containers, images, volumes, and networks, providing a comprehensive cleanup.

```
docker-compose down --rmi all
```
For deleting all images related to project.

6. #### Check Disk Usage:
```
docker system df
```
to get a general idea of ​​how much space images, containers, networks, and volumes are taking up.


## Usage

Once the forum is up and running:

1. Go to the homepage: http://localhost:8080
1. Register a new account.
1. Log in to create posts or comments, like or dislike.
1. Browse the forum by posts and interact with other users by likes and comments.
1. Filter posts by different categories on the homepage.
1. Search posts on the homepage for specific content or topic.
1. Explore user profile and see your posts, comments, liked content. 

### Extra Features
* A search bar allows user to search for specific posts or topics
* Users have access to profile pages.The profile allows the user to view posts and comments they have created or liked, with links to the full content of all posts listed.

### Contributors:

Julia Georgieva Georgieva, Mariia Melnikova, Tatiana Vedishcheva.
Hit us up in Discord if you have any questions!

