import { useQuery, useMutation } from "convex/react";
import { api as apiGeneric } from "../convex/_generated/api";
import { useState } from "react";
import { Id } from "../convex/_generated/dataModel";

const api = apiGeneric;

interface Thread {
  _id: Id<"threads">;
  title: string;
  createdAt: number;
}

export default function App() {
  const threads = useQuery(api.threads.list);
  const createThread = useMutation(api.threads.create);
  const deleteThread = useMutation(api.threads.deleteThread);
  const [newTitle, setNewTitle] = useState("");

  if (threads === undefined) {
    return <div>Loading...</div>;
  }

  return (
    <div className="p-10 container mx-auto">
      <h1 className="text-2xl font-bold mb-4">Chatbot Threads</h1>

      <div className="mb-8 flex gap-2">
        <input
          value={newTitle}
          onChange={e => setNewTitle(e.target.value)}
          className="border p-2 rounded flex-1 max-w-sm"
          placeholder="New Thread Title"
        />
        <button
          onClick={() => { createThread({ title: newTitle }); setNewTitle(""); }}
          className="bg-blue-500 text-white px-4 py-2 rounded hover:bg-blue-600"
        >
          Create
        </button>
      </div>

      <div className="space-y-2 max-w-2xl">
        {threads?.map((thread: Thread) => (
          <div key={thread._id} className="border p-4 rounded flex justify-between items-center shadow-sm">
            <div>
              <p className="font-medium">{thread.title}</p>
              <p className="text-xs text-gray-500">{new Date(thread.createdAt).toLocaleString()}</p>
            </div>
            <button
              onClick={() => deleteThread({ threadId: thread._id })}
              className="text-red-500 hover:text-red-700 px-3 py-1 border border-red-200 rounded text-sm"
            >
              Delete
            </button>
          </div>
        ))}
        {threads.length === 0 && (
          <p className="text-gray-500 italic">No threads found.</p>
        )}
      </div>
    </div>
  );
}
