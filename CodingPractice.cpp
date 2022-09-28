/* 
 * Data structures / algorithms implementation practice.
 *  Data structures:
 *      * Heap
 *      Hash Table
 *      Trie
 *      BST
 *      AVL-Tree
 *      Union-Find
 *      Skiplist
 *  algorithms:
 *      Quicksort
 *      Topological sort
 *      Merge sort
 *      Dijkstra
*/


#include <iostream>
#include <vector>
using namespace std;

class MinHeap {
    public:

    vector<int> _store;
    int _size;

    MinHeap() : _size(0) {}

    int empty() {
        return _size == 0;
    }

    int top() {
        if (empty()) {
            cout << "Error: empty heap" << endl;    
            return -1;
        }
        return _store[0];
    }
    
    void pop() {
        _store[0] = _store.back();
        _store.pop_back();
        _size -= 1;
        bubbleDown(0);
    }

    void push(int i) {
        _store.push_back(i);
        _size += 1;
        bubbleUp(_size-1);
    }

    void print() {
        cout << "Size = " << _size << ". ";
        for (auto i : _store) {
            cout << i << ", ";
        }
        cout << endl;
    }

    void heapify(vector<int>& v) {
        _store = v;
        _size = _store.size();
        for (int i=_size-1; i>=0; i--) {
            bubbleDown(i);
        }
    }

    private:
    
    int parent(int i) {
        if (i == 0) return -1;
        return (i-1) / 2;
    }

    int leftChild(int i) {
        int l = 2 * i + 1;
        return l >= _size ? -1 : l;
    }

    int rightChild(int i) {
        int r = 2 * i + 2;
        return r >= _size ? -1 : r;
    }

    void bubbleUp(int i) {
        int p = parent(i);
        // Compare to the parent
        if (p == -1 || _store[i] >= _store[p]) {
            return;
        }
        // Switch position
        swap(_store[i], _store[p]);
        bubbleUp(p);
    }

    void bubbleDown(int i) {
        int lc = leftChild(i), rc = rightChild(i);
        int toSwitch = -1;
        if (lc == -1 && rc == -1) {
            return;
        } else if (lc == -1) {
            if (_store[i] >= _store[rc])
                toSwitch = rc;
        } else if (rc == -1) {
            if (_store[i] >= _store[lc])
                toSwitch = lc;
        } else {
            int minChild = _store[lc] < _store[rc] ? lc : rc;
            if (_store[i] > _store[minChild])
                toSwitch = minChild;
        }
        if (toSwitch == -1) return;
        swap(_store[i], _store[toSwitch]);
        bubbleDown(toSwitch);
    }
};

int main() {
    /* Heap Testing */
    MinHeap h;
    vector<int> v{5, 6, 2, 3, 1, 4};
    // for (auto i : v) {
    //     h.push(i);
    // }
    h.heapify(v);
    while (!h.empty()) {
        cout << h.top() << ", ";
        h.pop();
    }
    cout << endl;

    return 0;
}
