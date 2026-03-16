// SAFE: Using DOMPurify to sanitize before rendering
import DOMPurify from 'dompurify';
function UserComment({ comment }) {
  const clean = DOMPurify.sanitize(comment.body);
  return <div>{clean}</div>;
}
