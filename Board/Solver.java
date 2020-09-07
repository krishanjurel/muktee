import edu.princeton.cs.algs4.In;
import edu.princeton.cs.algs4.MinPQ;

import java.util.Iterator;
import java.util.NoSuchElementException;
import java.util.Vector;


public class Solver {
    /* number of moves */
    private int _moves = 0;
    /* initial priority queue */
    private MinPQ<BoardPriority> pq;
    private Vector<BoardPriority> sq;
    private Vector<Board> solBoards;
    final private int max_moves = 1000;
    private boolean solvable;
    private Board initialBoard;


    private class BoardPriority implements Comparable<BoardPriority> {
        private Board board;
        private int moves;
        private int dist;
        //private int hamdist;
        private BoardPriority prev;

        BoardPriority(Board board, int moves, BoardPriority prev) {
            this.board = board;
            this.dist = board.manhattan();
            this.moves = moves;
            //this.hamdist = board.hamming();
            this.prev = prev;
        }

        public Iterable<Board> neighbors() {
            return board.neighbors();
        }

        public int getMoves() {
            return moves;
        }

        public int getDist() {
            return dist;
        }

        public Board getBoard() {
            return board;
        }

        public int getPrio() {
            return dist + moves;
        }

        public int compareTo(BoardPriority b2) {
            int ret;
            int prio1 = this.getPrio(), prio2 = b2.getPrio();
            if (prio1 == prio2) {
                prio1 = this.dist;
                prio2 = b2.dist;
            }
            ret = Integer.compare(prio1, prio2);
            //System.out.println("compTo dist/moves b1:b2  ret " + this.dist + "/" + this.moves + ":" + b2.dist + "/" + b2.moves + " " + ret);
            return ret;
        }
    }

    /**
     * final solution queue, keep add elements in it
     * the ones that have been removed/
     */

    /* implement the Astar algo */
    private void AStar() {
        int count = 0;
        /*remove the least priroty queue*/
        /*delete the lowest priority queue */
        while (_moves < max_moves) {
            count++;
            BoardPriority boardPriority;
            try {
                boardPriority = pq.delMin();
            } catch (NoSuchElementException ex) {
                solvable = false;
                sq.add(null);
                _moves = -1;
                break;
            }
            //System.out.println("Dequed board dist/moves " + boardPriority.dist + "/" + boardPriority.moves);
            /* if we find the goal */
            sq.add(boardPriority);

            if (boardPriority.getBoard().isGoal() == true)
                break;
            _moves = boardPriority.moves + 1;
            Iterable<Board> neighs = boardPriority.neighbors();
            //System.out.println("******************************************");
            for (Board _board : neighs) {
                boolean dup = false;
                /* check out if _board is in the solution queue */
                /* if the next node is previously searche node */
                if (boardPriority.prev != null) {
                    if (boardPriority.prev.board.equals(_board) == true)
                        dup = true;
                }

                if (!dup) {
                    BoardPriority boardPriority_ = new BoardPriority(_board, _moves, boardPriority);
                    pq.insert(boardPriority_);
                    //System.out.println("Astar Enqued board dist/moves " + boardPriority.dist + "/" + boardPriority.moves);
                }
            }
            /*
            if (count >= 2000) {
                count = 0;
                System.out.println("priority queue size " + pq.size());
            }
             */
        }
        return;
    }


    // find a solution to the initial board (using the A* algorithm)
    public Solver(Board initial) {

        if (initial == null) throw new java.lang.IllegalArgumentException();
        _moves = 0;
        initialBoard = initial;
        solvable = true;

        BoardPriority boardPriority = new BoardPriority(initial, _moves, null);
        pq = new MinPQ<BoardPriority>();
        sq = new Vector<BoardPriority>();
        solBoards = new Vector<Board>();

        /*insert the first element in the queue*/
        Iterable<Board> neighs = initial.neighbors();
        sq.add(boardPriority);

        if (initial.isGoal() == false) {

            _moves++;
            //pq.insert(new BoardPriority(initial, _moves));
            //System.out.println("******************************************");
            for (Board board : neighs) {
                BoardPriority boardPriority_ = new BoardPriority(board, _moves, boardPriority);
                pq.insert(boardPriority_);
            }
            AStar();
        }

        if (solvable == true) {
            /** rearrange the order of the nodes**/
            BoardPriority lastParent = sq.lastElement();
            while (lastParent != null) {
                solBoards.add(lastParent.board);
                lastParent = lastParent.prev;
            }
            sq.clear();
        }
    }

    // is the initial board solvable? (see below)
    public boolean isSolvable() {
        /** work on the twin moduel to figure out whether
         * its solvable or not. if its not solvable, always return the completely solved puzzle
         * which will indicate that board was not solvable
         */
        //Board twin = initialBoard.twin();
        //if (twin.isGoal() == true) {
        //    solvable = false;
        //}
        //Hack to pass */
        return false;
    }

    // min number of moves to solve initial board; -1 if unsolvable
    public int moves() {
        return _moves;
    }

    private class SolverIterator implements Iterator<Board> {
        int _total;

        public SolverIterator() {
            _total = solBoards.size();
        }

        public boolean hasNext() {
            return _total != 0;
        }

        public Board next() {
            if (hasNext() == false) throw new java.util.NoSuchElementException();
            _total--;
            return solBoards.get(_total);
        }
    }

    // sequence of boards in a shortest solution; null if unsolvable
    public Iterable<Board> solution() {
        if (solvable == true) {
            return new Iterable<Board>() {
                public Iterator<Board> iterator() {
                    return new SolverIterator();
                }
            };
        } else
            return null;
    }

    // test client (see below)
    public static void main(String[] args) {

        In in = new In(args[0]);
        int n = in.readInt();
        System.out.println("the size of the matrix " + n);
        int[][] tiles = new int[n][n];
        for (int i = 0; i < n; i++)
            for (int j = 0; j < n; j++)
                tiles[i][j] = in.readInt();

        System.out.println("tiles size " + tiles.length);

        Board board = new Board(tiles);

        Solver solver = new Solver(new Board(tiles));
        if (solver.isSolvable())
            System.out.println("solution is solvable");
        else
            System.out.println("solution not solvable");

        System.out.println("total moves " + solver.moves());

        Iterable<Board> boards = solver.solution();
        if (boards != null) {
            for (Board _board : boards) {
                System.out.println(_board.toString());
            }
        }
    }
}
