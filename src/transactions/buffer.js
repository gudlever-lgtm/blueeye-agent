'use strict';

// Bounded FIFO buffer for transaction results while offline. Holds at most `max`
// rows; on overflow the OLDEST row is dropped (a stale result matters less than a
// fresh one). drain() removes and returns everything (for a batch flush).
function createResultBuffer({ max = 1000 } = {}) {
  const items = [];
  let dropped = 0;

  function push(item) {
    items.push(item);
    while (items.length > max) { items.shift(); dropped += 1; }
  }

  function pushAll(arr) { for (const it of arr || []) push(it); }

  return {
    push,
    pushAll,
    size: () => items.length,
    droppedCount: () => dropped,
    drain: () => items.splice(0, items.length),
    peek: () => items.slice(),
  };
}

module.exports = { createResultBuffer };
