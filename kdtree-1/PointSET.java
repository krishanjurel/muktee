import edu.princeton.cs.algs4.Point2D;
import edu.princeton.cs.algs4.RectHV;
import edu.princeton.cs.algs4.StdOut;

import java.util.Iterator;
import java.util.NavigableSet;
import java.util.TreeSet;

public class PointSET {

    private TreeSet<Point2D> treeSet;
    private int num;

    public PointSET()                               // construct an empty set of points
    {
        treeSet = new TreeSet<Point2D>();
        num = 0;
    }

    public boolean isEmpty()                      // is the set empty?
    {
        return treeSet.size() == 0;
    }

    public int size()                         // number of points in the set
    {
        return treeSet.size();
    }

    public void insert(Point2D p)              // add the point to the set (if it is not already in the set)
    {
        if (p == null) throw new java.lang.IllegalArgumentException();

        if (contains(p) == false)
            treeSet.add(p);
    }

    public boolean contains(Point2D p)            // does the set contain point p?
    {
        if (p == null) throw new java.lang.IllegalArgumentException();
        return treeSet.contains(p);
    }

    public void draw()                         // draw all points to standard draw
    {
        if (treeSet.size() == 0) throw new java.lang.IllegalArgumentException();

        Iterator<Point2D> itr = treeSet.iterator();
        while (itr.hasNext() == true) {
            Point2D point = itr.next();
            point.draw();
        }
    }

    public Iterable<Point2D> range(RectHV rect)             // all points that are inside the rectangle (or on the boundary)
    {
        NavigableSet<Point2D> navigableSet = treeSet.subSet(new Point2D(rect.xmin(), rect.ymin()), true, new Point2D(rect.xmax(), rect.ymax()), true);
        return new Iterable<Point2D>() {
            public Iterator<Point2D> iterator() {
                return navigableSet.iterator();
            }
        };
    }

    public Point2D nearest(Point2D p)             // a nearest neighbor in the set to point p; null if the set is empty
    {
        Point2D point = null;
        if (treeSet.isEmpty()) throw new java.lang.IllegalArgumentException();
        /* hack, find the floor and ceiling, and return whichever is smaller */
        Point2D floor = treeSet.floor(p);
        Point2D ceiling = treeSet.ceiling(p);
        if (floor != null && ceiling != null) {
            point = ceiling;
            if (floor.compareTo(ceiling) < 0)
                point = floor;

            StdOut.println("Floor" + floor.toString());
            StdOut.println("Ceiling" + ceiling.toString());
        } else if (floor == null) point = ceiling;
        else if (ceiling == null) point = floor;

        if (point == null) throw new java.lang.IllegalArgumentException();

        StdOut.println("Point" + point.toString());
        return point;
    }

    public static void main(String[] args)                  // unit testing of the methods (optional)
    {

    }
}
