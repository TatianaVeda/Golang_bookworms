DELETE FROM post_categories;
DELETE FROM comments;
DELETE FROM likes_dislikes;
DELETE FROM posts;
DELETE FROM categories;
DELETE FROM users;


-- Insert data into users table
INSERT INTO users (email, username, password, is_admin) 
VALUES 
    ('bob@bob.bob', 'bob', 'bob', 1), -- bob is an admin
    ('user1@example.com', 'user1', 'hashedpassword2', 0),
    ('user2@example.com', 'user2', 'hashedpassword3', 0);

-- Insert data into categories table
INSERT INTO categories (name) 
VALUES 
    ('Technology'),
    ('Literature'),
    ('Music'),
    ('Art');

-- Insert data into posts table
INSERT INTO posts (title, body, user_id, category_id) 
VALUES 
    ('First Post on Technology', 'This is a post about technology.', 2, 1),
    ('Exploring Literature', 'A post discussing modern literature.', 3, 2),
    ('The Beauty of Classical Music', 'This post is all about classical music.', 2, 3);

-- Insert data into post_categories table
INSERT INTO post_categories (post_id, category_id) VALUES (1, 2);
INSERT INTO post_categories (post_id, category_id) VALUES (1, 3);


-- Insert data into comments table
INSERT INTO comments (body, post_id, user_id) 
VALUES 
    ('Great post! I love technology too.', 1, 1),
    ('I disagree with some points.', 2, 2),
    ('Amazing read on classical music!', 3, 1);

-- Insert data into likes_dislikes table (posts)
INSERT INTO likes_dislikes (user_id, post_id, like_type) 
VALUES 
    (1, 1, 1),  -- Ana likes first post
    (2, 2, 1),  -- user1 likes second post
    (3, 1, -1); -- user2 dislikes the first post

-- Insert data into comment_likes table (comments)
INSERT INTO comment_likes (user_id, comment_id, like) 
VALUES 
    (1, 1, 1),  -- Ana likes first comment
    (2, 2, 1),  -- user1 likes second comment
    (3, 3, 1);  -- user2 likes third comment
