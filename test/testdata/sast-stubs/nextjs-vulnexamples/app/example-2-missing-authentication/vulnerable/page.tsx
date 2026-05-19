import { getPublishedBlogPosts } from '../../../database/blogPosts';

export const dynamic = 'force-dynamic';

// VULNERABILITY: No authentication check - renders blog posts to any visitor
export default async function MissingAuthenticationServerComponentPage() {
  const blogPosts = await getPublishedBlogPosts();

  return (
    <div>
      <h1>Blog Posts</h1>
      {blogPosts.map((post) => (
        <article key={`post-${post.id}`}>
          <h2>{post.title}</h2>
          <p>{post.textContent}</p>
        </article>
      ))}
    </div>
  );
}
