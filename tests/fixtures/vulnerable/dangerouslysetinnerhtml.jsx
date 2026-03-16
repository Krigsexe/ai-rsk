// VULNERABLE: dangerouslySetInnerHTML with dynamic user content
function UserComment({ comment }) {
  return <div dangerouslySetInnerHTML={{ __html: comment.body }} />;
}
