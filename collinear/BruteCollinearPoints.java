import java.util.Comparator;
import java.util.Iterator;


public class BruteCollinearPoints implements Iterable<LineSegment> {
    private Point[] points;
    private LineSegment[] lineSegments;
    private int numberOfSegments;

    BruteCollinearPoints(Point[] points) {
        this.points = points;
        numberOfSegments = 0;
        lineSegments = new LineSegment[points.length * 4];
        for (int i = 0; i < points.length - 2; ) {
            Comparator<Point> c = points[i].slopeOrder();
            for (int j = i + 1; j < points.length - 1; j++) {
                if (c.compare(points[j], points[j + 1]) == c.compare(points[i], points[j])) {
                    lineSegments[numberOfSegments++] = new LineSegment(points[i], points[j]);
                    lineSegments[numberOfSegments++] = new LineSegment(points[j], points[j + 1]);
                }
                System.out.println("number of segments " + numberOfSegments);
            }
            i++;
        }
    }

    public Iterator<LineSegment> iterator() {
        return new LineSegmentIterator();
    }

    public LineSegment[] segments() {
        return lineSegments;
    }

    private class LineSegmentIterator implements Iterator<LineSegment> {
        private LineSegment[] segments = lineSegments;
        private int totalCount = numberOfSegments;
        private int i = 0;

        public boolean hasNext() {
            return i < totalCount;
        }

        public LineSegment next() {
            if (hasNext() == false) throw new java.util.NoSuchElementException();
            return segments[i++];
        }
    }
}
