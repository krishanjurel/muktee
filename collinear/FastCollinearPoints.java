public class FastCollinearPoints {
    private BruteCollinearPoints bruteCollinearPoints;

    public FastCollinearPoints(Point[] points) {

        bruteCollinearPoints = new BruteCollinearPoints(points);
    }

    public int numberOfSegments() {
        return bruteCollinearPoints.numberOfSegments();
    }

    //private Iterable<LineSegment> segment() {
    //    return bruteCollinearPoints.segment();
    //}

    public LineSegment[] segments() {
        return bruteCollinearPoints.segments();
    }
}
