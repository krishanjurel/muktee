import edu.princeton.cs.algs4.Point2D;
import edu.princeton.cs.algs4.RectHV;

import java.util.ArrayList;
import java.util.Iterator;
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
        return treeSet.isEmpty();
    }

    public int size()                         // number of points in the set
    {
        return treeSet.size();
    }

    public void insert(
            Point2D p)              // add the point to the set (if it is not already in the set)
    {
        if (p == null) throw new java.lang.IllegalArgumentException();
        ++num;

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

        Iterator<Point2D> itr = treeSet.iterator();
        while (itr.hasNext() == true) {
            Point2D point = itr.next();
            point.draw();
        }
    }

    // all points that are inside the rectangle (or on the boundary)
    public Iterable<Point2D> range(RectHV rect) {
        if (rect == null) throw new java.lang.IllegalArgumentException();
        double reflowx = rect.xmin();
        double reflowy = rect.ymin();
        double refhix = rect.xmax();
        double refhiy = rect.ymax();
        double x;
        double y;
        Point2D point;

        ArrayList<Point2D> vec = new ArrayList<Point2D>();
        Iterator<Point2D> itr = treeSet.iterator();
        while (itr.hasNext() == true) {
            point = itr.next();
            x = point.x();
            y = point.y();
            if (x >= reflowx && x <= refhix && y >= reflowy && y <= refhiy) vec.add(point);
        }
        return vec;
    }

    public Point2D nearest(
            Point2D p)             // a nearest neighbor in the set to point p; null if the set is empty
    {
        Point2D point = null;
        Point2D nearest = null;
        double mindist = -1;
        double dist = 0.0;
        if (p == null) throw new java.lang.IllegalArgumentException();

        Iterator<Point2D> itr = treeSet.iterator();
        while (itr.hasNext() == true) {
            point = itr.next();
            dist = p.distanceSquaredTo(point);
            /* first initilization */
            if (mindist == -1) {
                mindist = dist;
                nearest = point;
            }
            if (mindist > dist) {
                mindist = dist;
                nearest = point;
            }
        }
        //if (point == null) throw new java.lang.IllegalArgumentException();
        //StdOut.println("treeset nearest " + point.toString());
        return nearest;
    }

    public static void main(
            String[] args)                  // unit testing of the methods (optional)
    {

    }
}
