# Code Quality Audit Report

## 1. Resilience: `os.replace` crashes on cross-device links
- **File(s) and lines:** `text_aggregator.py`, lines 859-860 (`AttestedBuilder.finalize`)
- **The specific problem:** The code uses `os.replace(self.spool_path, self.output_path)` to move the final document from the temporary directory to the destination.
- **Why it matters:** `os.replace` does not support moving files across different filesystems (e.g., from a `/tmp` RAM disk to a persistent drive). This will cause the program to crash at the very end of processing with an `OSError: [Errno 18] Invalid cross-device link`, losing all aggregated work.
- **Proposed fix:** Import `shutil` and replace `os.replace` with `shutil.move(str(self.spool_path), str(self.output_path))`, which gracefully falls back to copying and deleting if the atomic rename fails.
- **Overlap:** None.

## 2. Memory / Resilience: `re.findall` loads all words into memory
- **File(s) and lines:** `text_aggregator.py`, line 769 (`BoundedExtractionEngine._count`)
- **The specific problem:** Word counting is implemented as `len(re.findall(r"\w+", text, re.UNICODE))`, which creates a list of every single matched word string in memory simultaneously.
- **Why it matters:** For large files, creating a list of millions of strings bypasses the affine memory bounds and will cause abrupt Out-Of-Memory (OOM) crashes, making the memory accounting ineffective.
- **Proposed fix:** Use an iterator generator with `sum()` and `re.finditer` to count words without allocating a list:
  ```python
  words = sum(1 for _ in re.finditer(r"\w+", text, re.UNICODE))
  ```
- **Overlap:** None.

## 3. Redundant Work: N+1 query problem in chunk deduplication
- **File(s) and lines:** `text_aggregator.py`, lines 729-734 (`BoundedExtractionEngine.extract`)
- **The specific problem:** The chunk-level deduplication loop evaluates `if not self.checkpoint.has_chunk(h)` inside a list comprehension, running a separate synchronous `SELECT` query for every individual chunk.
- **Why it matters:** A file containing 10,000 chunks will trigger 10,000 individual database queries, completely locking up the database and blocking the parallel extraction thread due to massive I/O overhead.
- **Proposed fix:** Batch the existence check into a single query for the file's chunks.
  ```python
  chunk_hashes = [h for _, h in chunks]
  if chunk_hashes:
      placeholders = ",".join("?" * len(chunk_hashes))
      existing = {
          row[0] for row in self.checkpoint._conn().execute(
              f"SELECT chunk_hash FROM chunks WHERE chunk_hash IN ({placeholders})",
              chunk_hashes
          )
      }
  else:
      existing = set()
  new_chunks = [(ch, h) for ch, h in chunks if h not in existing]
  ```
- **Overlap:** None.

## 4. Redundant Work: Single row inserts instead of `executemany`
- **File(s) and lines:** `text_aggregator.py`, lines 661-667 (`CheckpointManager.record`)
- **The specific problem:** The code iterates over `record.chunks` and calls `conn.execute(...)` for each chunk individually to insert them into the SQLite database.
- **Why it matters:** SQLite incurs significant transaction and virtual machine overhead for individual `INSERT` statements. Doing this thousands of times per file dramatically degrades write throughput.
- **Proposed fix:** Replace the loop with `executemany` for bulk insertion:
  ```python
  if record.chunks:
      conn.executemany(
          """
          INSERT OR IGNORE INTO chunks (chunk_hash, file_hash)
          VALUES (?, ?)
          """,
          [(chunk_hash, record.content_hash) for chunk_hash, _ in record.chunks]
      )
  ```
- **Overlap:** None.

## 5. Correctness Risk: Dynamic `@functools.lru_cache` defeats memoization
- **File(s) and lines:** `text_aggregator.py`, lines 212 and 237 (`GitignoreMatcher._match_components` and `_match_glob`)
- **The specific problem:** The `dfs` inner functions are decorated with `@functools.lru_cache(maxsize=None)`. Because they are defined locally within the static methods, a brand new cache is initialized and discarded on every single call to `_match_components`.
- **Why it matters:** This completely nullifies cross-call caching while adding the heavy performance overhead of dynamically constructing and tearing down the `lru_cache` wrapper for every file path evaluated.
- **Proposed fix:** Use a manual `memo` dictionary defined outside the `dfs` function but inside the static method:
  ```python
  memo = {}
  def dfs(pi: int, pj: int) -> bool:
      if (pi, pj) in memo: return memo[(pi, pj)]
      # ... compute result ...
      memo[(pi, pj)] = result
      return result
  ```
- **Overlap:** None.

## 6. Resilience: Immediate failure on memory budget exhaustion
- **File(s) and lines:** `text_aggregator.py`, lines 685-690 (`BoundedExtractionEngine._bounded_read`)
- **The specific problem:** If `self.budget.allocate` exceeds the affine limit, it immediately raises a `MemoryError`, which bubbles up and marks the file as unprocessable.
- **Why it matters:** In a threaded I/O workload, temporary budget exhaustion is expected as other threads are holding memory. Failing immediately degrades output quality by skipping valid files instead of waiting gracefully for memory to free up.
- **Proposed fix:** Wait for memory to become available using a loop if the file size fits within the max limit:
  ```python
  if size > self.budget.limit_bytes:
      raise MemoryError(f"File {filepath.name} exceeds total memory limit.")
  while True:
      with self._budget_lock:
          try:
              new_budget = self.budget.allocate(size, f"read_{filepath.name}")
              self.budget = new_budget
              break
          except MemoryError:
              pass
      time.sleep(0.05)
  ```
- **Overlap:** None.

## 7. Bug: Unintentional hardcoding of `--ignore` negation flags
- **File(s) and lines:** `text_aggregator.py`, lines 976-977 (`Processor._collect_files`)
- **The specific problem:** Custom ignore patterns supplied via `self.extra_ignore` are passed to `add_rule` with `negation=False`, regardless of whether the pattern starts with `!`.
- **Why it matters:** If a user specifies a negation flag via the CLI (e.g., `--ignore '!*.txt'`), the system treats the literal string `!*.txt` as the target, completely breaking the user's exclusion override.
- **Proposed fix:** Parse and strip the negation character dynamically before adding the rule:
  ```python
  for pat in self.extra_ignore:
      neg = pat.startswith("!")
      if neg:
          pat = pat[1:]
      matcher.add_rule(pat, negation=neg, base_parts=[])
  ```
- **Overlap:** None.

## 8. Correctness Risk: Deduplicated files emit misleading output headers
- **File(s) and lines:** `text_aggregator.py`, lines 816-817 (`AttestedBuilder.write_file`)
- **The specific problem:** The early return guard specifically allows `DUPLICATE` and `CHECKPOINTED` error types to proceed to header generation, even though their content, line counts, and word counts are hardcoded to zero.
- **Why it matters:** The final output document gets cluttered with misleading file headers reporting `0 lines` and `0 words` for large deduplicated files, and these files are stealthily omitted from the Merkle tree, corrupting the document's attestation accuracy.
- **Proposed fix:** Prevent writing anything for deduplicated files by simplifying the error guard to catch all errors:
  ```python
  if record.error:
      return
  ```
- **Overlap:** None.

## 9. Resilience: Signal handler `sys.exit` disrupts curses terminal restoration
- **File(s) and lines:** `text_aggregator.py`, lines 1180-1183 (`main._sigint_handler`)
- **The specific problem:** Catching `SIGINT` executes `sys.exit(130)`. When running in curses mode, this immediately halts execution and aborts the terminal restoration sequence handled by `curses.wrapper`.
- **Why it matters:** Pressing `Ctrl+C` leaves the user's terminal in an unresponsive, corrupted state (invisible cursor, raw keyboard inputs), forcing them to run `reset` to regain control.
- **Proposed fix:** Raise `KeyboardInterrupt` instead of calling `sys.exit`, allowing the exception to bubble up through `curses.wrapper` so the terminal is properly restored before termination:
  ```python
  def _sigint_handler(signum, frame):
      processor.executor.shutdown(wait=False)
      raise KeyboardInterrupt()
  ```
- **Overlap:** None.

## 10. Memory / Resilience: Unbounded `ThreadPoolExecutor` task queue
- **File(s) and lines:** `text_aggregator.py`, lines 1011-1012 (`Processor.run`)
- **The specific problem:** `self.executor.submit(...)` is invoked in a rapid loop for every discovered file in the project. `ThreadPoolExecutor` uses an unbounded internal queue.
- **Why it matters:** Scanning a massive codebase with hundreds of thousands of files instantly generates hundreds of thousands of concurrent closure objects in the thread queue, causing immense memory pressure and circumventing the strictly bound memory budget.
- **Proposed fix:** Use a `threading.Semaphore` initialized to `MAX_WORKERS * 2` inside `DeterministicExecutor`. Acquire the semaphore before submitting the task, and release it inside `drain_ordered` when a result is popped off the queue, creating a bounded producer-consumer backpressure.
- **Overlap:** None.

## 11. Dead Code: Unused `budget` variable in `AttestedBuilder`
- **File(s) and lines:** `text_aggregator.py`, lines 793 and 797 (`AttestedBuilder.__init__`)
- **The specific problem:** The `budget` parameter passed into `AttestedBuilder` is assigned to `self.budget` but is completely ignored throughout the class lifecycle.
- **Why it matters:** Retaining stale, unused state objects obfuscates the data flow, confusing maintainers into believing the builder is actively tracking memory allocations when it is not.
- **Proposed fix:** Remove the `budget` argument from `AttestedBuilder.__init__` and delete `self.budget = budget`. Similarly, remove `self.budget` from the initialization call in `Processor.__init__` (line 964).
- **Overlap:** None.
